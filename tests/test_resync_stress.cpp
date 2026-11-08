#include "rawio_sync.hpp"
#include "tmp_dir.hpp"

#include <ost/server.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/pipe.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <pthread.h>
#include <signal.h>
#include <unistd.h>

/*
 * Several writable opens of one mirrored object (one per virtqueue of
 * rawstor-vhost) keep writing while the OSTs holding its members stop and
 * come back: the resync of a returning member starts and ends under
 * concurrent writers. Every queue also reads back what it wrote, like a fio
 * job with verification, and a watchdog reports a queue that finishes
 * nothing for RAWSTOR_STRESS_HANG_S seconds.
 *
 * RAWSTOR_STRESS_SECONDS, _QUEUES, _SETTLE_MS, _PORT and _DOWN_MS (how long a
 * member stays down) tune a run. With RAWSTOR_STRESS_BLACKHOLE=1 a member is
 * powered off instead of stopped: its traffic is dropped, so its peers get
 * no close or reset until it is back, as when a host dies. That needs root
 * and a network namespace of its own, and the retry options of a real
 * deployment, for instance (a member down for longer than the retries last
 * is what exercises the replacement of its Slot):
 *
 *   sudo RAWSTOR_STRESS_BLACKHOLE=1 RAWSTOR_STRESS_SECONDS=200 \
 *       RAWSTOR_STRESS_DOWN_MS=70000 RAWSTOR_STRESS_SETTLE_MS=25000 \
 *       RAWSTOR_OPTS_IO_ATTEMPTS=10 RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE=100 \
 *       unshare -n sh -c 'ip link set lo up && \
 *       ./test_all --gtest_filter=ResyncStressTest.*'
 */

namespace {

int callback(size_t result, int error, void* data) {
    std::unique_ptr<std::function<void(size_t, int)>> cb(
        static_cast<std::function<void(size_t, int)>*>(data)
    );
    (*cb)(result, error);
    return 0;
}

class Queue {
private:
    RawIOQueue* _queue;

public:
    explicit Queue(unsigned int size) : _queue(nullptr) {
        int res = rawio_queue_create(size, &_queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;
    ~Queue() { rawio_queue_delete(_queue); }
    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;
    operator RawIOQueue*() noexcept { return _queue; }

    void wait() {
        int res = rawio_wait(_queue);
        // The test runs commands (iptables): their SIGCHLD may land here.
        if (res < 0 && res != -EINTR) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
};

// One rawstor-ost on a fixed port over a directory of its own, which can
// be stopped (its connections are dropped) and started again over the same
// data, like a host that was powered off and came back.
class OstArm {
private:
    rawstor::tests::TmpDir _dir;
    unsigned int _port;
    int _listen_fd = -1;
    int _wake_write_fd = -1;
    std::thread _thread;

public:
    explicit OstArm(unsigned int port) : _port(port) {}
    OstArm(const OstArm&) = delete;
    OstArm& operator=(const OstArm&) = delete;
    ~OstArm() { stop(); }

    void start() {
        _listen_fd =
            rawstor::ostserver::Server::bind_listen("127.0.0.1", _port);
        rawstd::Pipe wake(rawstd::Pipe::Mode::NonBlocking);
        _wake_write_fd = wake.release_write();
        int wake_read_fd = wake.release_read();
        std::string location = _dir.uri();
        int listen_fd = _listen_fd;
        std::promise<void> ready;
        std::future<void> ready_future = ready.get_future();
        _thread = std::thread([&ready, listen_fd, location, wake_read_fd]() {
            rawstor::ostserver::Server s(
                256, listen_fd, location.c_str(), wake_read_fd
            );
            ready.set_value();
            s.loop();
            close(wake_read_fd);
        });
        ready_future.get();
    }

    void stop() {
        if (!_thread.joinable()) {
            return;
        }
        char byte = 0;
        ssize_t ignored = write(_wake_write_fd, &byte, 1);
        (void)ignored;
        _thread.join();
        close(_wake_write_fd);
        close(_listen_fd);
        _wake_write_fd = -1;
        _listen_fd = -1;
    }

    std::string location(const std::string& uuid) const {
        std::ostringstream oss;
        oss << "ost://127.0.0.1:" << _port << "/" << uuid;
        return oss.str();
    }

    // This arm's copy of chunk 0 (a file:// directory).
    std::filesystem::path data_path(const std::string& uuid) const {
        return _dir.path() / uuid / "0" / "data";
    }

    // A host that is powered off: nothing it would send, not even the
    // close of its connections, reaches its peers, and what they send to it
    // is not answered, until it is powered on again and answers every
    // connection of its previous life with a reset. Needs root, iptables and
    // a network namespace of its own (the rules drop the port's traffic).
    void power_off() {
        _rules('I');
        stop();
    }

    void power_on() {
        _rules('D');
        start();
    }

private:
    void _rules(char op) {
        std::ostringstream cmd;
        for (const char* side : {"--dport", "--sport"}) {
            cmd << "iptables -w -" << op << " INPUT -p tcp " << side << " "
                << _port << " -j DROP >/dev/null 2>&1; ";
        }
        int res = std::system(cmd.str().c_str());
        (void)res;
    }
};

int write_once(
    Queue& queue, RawstorObject* object, const void* buf, size_t size,
    uint64_t offset
) {
    bool completed = false;
    int ret = 0;
    auto cb = std::make_unique<std::function<void(size_t, int)>>(
        [&completed, &ret](size_t, int error) {
            ret = error;
            completed = true;
        }
    );
    int res = rawstor_object_pwrite(
        object, buf, size, offset, false, callback, cb.get()
    );
    if (res < 0) {
        return -res;
    }
    cb.release();
    while (!completed) {
        queue.wait();
    }
    return ret;
}

int read_once(
    Queue& queue, RawstorObject* object, void* buf, size_t size, uint64_t offset
) {
    bool completed = false;
    int ret = 0;
    auto cb = std::make_unique<std::function<void(size_t, int)>>(
        [&completed, &ret, size](size_t result, int error) {
            ret = error != 0 ? error : (result == size ? 0 : EIO);
            completed = true;
        }
    );
    int res =
        rawstor_object_pread(object, buf, size, offset, callback, cb.get());
    if (res < 0) {
        return -res;
    }
    cb.release();
    while (!completed) {
        queue.wait();
    }
    return ret;
}

// What generation `gen` of block `block` of queue `q` holds: 4096 bytes
// of one 64-bit word each, zeros for a block never written.
void fill_block(char* dst, unsigned int q, uint64_t block, uint32_t gen) {
    uint64_t word = 0;
    if (gen != 0) {
        word = (static_cast<uint64_t>(q) << 56) ^
               (block * 0x9e3779b97f4a7c15ull) ^
               (static_cast<uint64_t>(gen) << 24) ^ 0x5a5a5a5a5a5a5a5aull;
    }
    for (size_t i = 0; i < 4096; i += sizeof(word)) {
        memcpy(dst + i, &word, sizeof(word));
    }
}

// The generation encoded in a block's first word (see fill_block()), or
// -1 when the word is not one fill_block() makes.
long decode_gen(uint64_t word, unsigned int q, uint64_t block) {
    if (word == 0) {
        return 0;
    }
    uint64_t x = word ^ (static_cast<uint64_t>(q) << 56) ^
                 (block * 0x9e3779b97f4a7c15ull) ^ 0x5a5a5a5a5a5a5a5aull;
    return (x & 0xffffff) == 0 ? static_cast<long>((x >> 24) & 0xffffffff)
                               : -1L;
}

long disk_gen(
    const std::filesystem::path& path, uint64_t offset, unsigned int q,
    uint64_t block
) {
    std::ifstream f(path, std::ios::binary);
    f.seekg(static_cast<std::streamoff>(offset));
    uint64_t word = 0;
    f.read(reinterpret_cast<char*>(&word), sizeof(word));
    return decode_gen(word, q, block);
}

unsigned int env_uint(const char* name, unsigned int fallback) {
    const char* v = getenv(name);
    return v != nullptr ? static_cast<unsigned int>(atoi(v)) : fallback;
}

} // unnamed namespace

TEST(ResyncStressTest, writers_survive_member_restarts) {
    if (env_uint("RAWSTOR_STRESS_BLACKHOLE", 0) != 0 && geteuid() != 0) {
        GTEST_SKIP() << "RAWSTOR_STRESS_BLACKHOLE needs root in a network "
                        "namespace of its own";
    }
    // The iptables commands raise SIGCHLD, which would interrupt the wait
    // of whichever thread gets it, a server's included, and end its loop.
    // Blocked here, before any thread starts, no thread gets it.
    sigset_t chld;
    sigemptyset(&chld);
    sigaddset(&chld, SIGCHLD);
    pthread_sigmask(SIG_BLOCK, &chld, nullptr);
    signal(SIGPIPE, SIG_IGN);

    const unsigned int seconds = env_uint("RAWSTOR_STRESS_SECONDS", 5);
    const unsigned int nqueues = env_uint("RAWSTOR_STRESS_QUEUES", 4);
    const unsigned int base_port = env_uint("RAWSTOR_STRESS_PORT", 17800);
    const std::string uuid = "018f4e2a-5000-7000-8000-0000000000a1";
    const uint64_t size = 64ull << 20;

    std::vector<std::unique_ptr<OstArm>> arms;
    for (unsigned int i = 0; i < 3; ++i) {
        arms.push_back(std::make_unique<OstArm>(base_port + i));
        arms.back()->start();
    }
    std::string target = arms[0]->location(uuid) + "," +
                         arms[1]->location(uuid) + "," +
                         arms[2]->location(uuid);

    {
        Queue queue(8);
        RawstorObjectSpec spec{};
        spec.size = size;
        spec.width = 2;
        ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
            return rawstor_target_create(
                queue, target.c_str(), &spec, cb, data
            );
        });
        ASSERT_EQ(res, 0);
    }

    std::atomic<bool> stop{false};
    std::atomic<unsigned long> writes{0};
    std::atomic<unsigned long> failures{0};
    std::atomic<unsigned long> errors[256] = {};
    constexpr unsigned int counters = 4096;
    std::atomic<unsigned long> ok_per_sec[counters] = {};
    // Successful writes of each queue, and how many queues opened.
    std::vector<std::atomic<unsigned long>> queue_ok(nqueues);
    std::atomic<unsigned int> opened{0};
    std::atomic<unsigned int> open_failed{0};
    std::atomic<unsigned long> verify_failures{0};
    std::atomic<unsigned long> reads{0};
    // When each queue last finished an operation, in steady_clock ticks.
    std::vector<std::atomic<long>> queue_alive(nqueues);
    const bool blackhole = env_uint("RAWSTOR_STRESS_BLACKHOLE", 0) != 0;
    auto t0 = std::chrono::steady_clock::now();
    std::vector<std::thread> writers;
    for (unsigned int q = 0; q < nqueues; ++q) {
        writers.emplace_back([&, q]() {
            Queue queue(64);
            RawstorObject* object = nullptr;
            ssize_t res =
                rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
                    return rawstor_target_open(
                        queue, target.c_str(), 0, &object, cb, data
                    );
                });
            if (res < 0) {
                open_failed += 1;
                return;
            }
            opened += 1;
            std::mt19937_64 rng(q + 1);
            // The queue owns one region of the object, so what it wrote is
            // what it must read back, like a fio job with verification.
            const uint64_t region_blocks = size / 4096 / nqueues;
            const uint64_t region_off = q * region_blocks * 4096;
            std::vector<uint32_t> gen(region_blocks, 0);
            std::vector<char> known(region_blocks, 1);
            uint32_t next_gen = 0;
            std::vector<char> buf(512 << 10), rbuf(512 << 10);
            while (!stop) {
                size_t nblocks = (rng() % 127) + 1;
                uint64_t start = rng() % (region_blocks - nblocks);
                size_t len = nblocks * 4096;
                uint64_t off = region_off + start * 4096;
                int err;
                const bool do_read = (rng() % 2) == 0;
                if (do_read) {
                    err = read_once(queue, object, rbuf.data(), len, off);
                    reads += 1;
                    if (err == 0) {
                        std::vector<char> want(4096);
                        for (size_t i = 0; i < nblocks; ++i) {
                            if (!known[start + i]) {
                                continue;
                            }
                            fill_block(
                                want.data(), q, start + i, gen[start + i]
                            );
                            if (memcmp(
                                    rbuf.data() + i * 4096, want.data(), 4096
                                ) != 0) {
                                if (verify_failures++ < 8) {
                                    uint64_t word;
                                    memcpy(&word, rbuf.data() + i * 4096, 8);
                                    uint64_t abs_off =
                                        region_off + (start + i) * 4096;
                                    std::cerr << "VERIFY queue " << q
                                              << " block " << start + i
                                              << " expected gen "
                                              << gen[start + i] << " read gen "
                                              << decode_gen(word, q, start + i)
                                              << ", on disk: arm0 "
                                              << disk_gen(
                                                     arms[0]->data_path(uuid),
                                                     abs_off, q, start + i
                                                 )
                                              << " arm1 "
                                              << disk_gen(
                                                     arms[1]->data_path(uuid),
                                                     abs_off, q, start + i
                                                 )
                                              << std::endl;
                                }
                            }
                        }
                    }
                } else {
                    ++next_gen;
                    for (size_t i = 0; i < nblocks; ++i) {
                        fill_block(
                            buf.data() + i * 4096, q, start + i, next_gen
                        );
                    }
                    err = write_once(queue, object, buf.data(), len, off);
                    for (size_t i = 0; i < nblocks; ++i) {
                        if (err == 0) {
                            gen[start + i] = next_gen;
                            known[start + i] = 1;
                        } else {
                            known[start + i] = 0;
                        }
                    }
                }
                writes += 1;
                queue_alive[q] =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - t0
                    )
                        .count();
                if (err != 0) {
                    failures += 1;
                    errors[err & 255] += 1;
                } else {
                    auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::steady_clock::now() - t0
                    )
                                   .count();
                    ok_per_sec[std::min<unsigned long>(sec, counters - 1)] += 1;
                    queue_ok[q] += 1;
                }
            }
            rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
                return rawstor_object_close(object, cb, data);
            });
        });
    }

    auto finish_writers = [&]() {
        stop = true;
        for (auto& t : writers) {
            if (t.joinable()) {
                t.join();
            }
        }
    };

    for (auto& a : queue_alive) {
        a = 0;
    }
    // Every writer must have opened before the outages start: a queue that
    // did not would leave the others to carry the progress checks.
    while (opened + open_failed < nqueues) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    if (opened != nqueues) {
        finish_writers();
        FAIL() << open_failed << " of " << nqueues << " writers did not open";
    }

    std::mt19937_64 rng(12345);
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    const unsigned int settle_ms = env_uint("RAWSTOR_STRESS_SETTLE_MS", 6000);
    // How long a member stays down; 0 is a random 0.1-1.6 s.
    const unsigned int down_ms = env_uint("RAWSTOR_STRESS_DOWN_MS", 0);
    std::vector<unsigned long> ok_at_check(nqueues, 0);
    unsigned int dead_windows = 0;
    // A queue that finishes nothing for this long is hung: report the
    // members and give up, the writer cannot be joined.
    const long hang_ms = env_uint("RAWSTOR_STRESS_HANG_S", 120) * 1000L;
    std::atomic<bool> watching{true};
    std::thread watchdog([&]() {
        while (watching) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
            long now = std::chrono::duration_cast<std::chrono::milliseconds>(
                           std::chrono::steady_clock::now() - t0
            )
                           .count();
            for (unsigned int q = 0; q < nqueues; ++q) {
                if (now - queue_alive[q] > hang_ms) {
                    std::cerr << "HANG queue " << q << " idle for "
                              << (now - queue_alive[q]) / 1000 << " s"
                              << std::endl;
                    // The members' answer may hang too: give up on it.
                    alarm(30);
                    Queue queue(8);
                    RawstorObjectMeta metas[3]{};
                    ssize_t res = rawstor::tests::sync_run(
                        queue, [&](auto cb, void* data) {
                            return rawstor_target_meta(
                                queue, target.c_str(), metas, 3, cb, data
                            );
                        }
                    );
                    static const char* names[] = {
                        "UNREACHABLE", "CLEAN", "DIRTY", "LOST"
                    };
                    std::cerr << "HANG members (res " << res << "):";
                    for (int i = 0; i < 3; ++i) {
                        std::cerr << " [" << i << " " << names[metas[i].state]
                                  << " w=" << metas[i].writers << "]";
                    }
                    std::cerr << std::endl;
                    _exit(3);
                }
            }
        }
    });
    while (std::chrono::steady_clock::now() < deadline) {
        unsigned int victim = static_cast<unsigned int>(rng() % 2);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(300 + rng() % 1500)
        );
        std::cerr << "CHAOS stop arm " << victim << std::endl;
        if (blackhole) {
            arms[victim]->power_off();
        } else {
            arms[victim]->stop();
        }
        std::this_thread::sleep_for(
            std::chrono::milliseconds(
                down_ms != 0 ? down_ms : 100 + rng() % 1500
            )
        );
        std::cerr << "CHAOS start arm " << victim << std::endl;
        if (blackhole) {
            arms[victim]->power_on();
        } else {
            arms[victim]->start();
        }
        // One outage at a time: the returned member gets its resync before
        // the next one goes down, and writes must be going on again.
        std::this_thread::sleep_for(std::chrono::milliseconds(settle_ms));
        // Every queue, not just the sum of them, must have written since
        // the last check.
        for (unsigned int q = 0; q < nqueues; ++q) {
            unsigned long ok_now = queue_ok[q];
            if (ok_now == ok_at_check[q]) {
                ++dead_windows;
                std::cerr << "queue " << q << " made no progress" << std::endl;
            }
            ok_at_check[q] = ok_now;
        }
    }
    static const char* names[] = {"UNREACHABLE", "CLEAN", "DIRTY", "LOST"};
    auto read_meta = [&](RawstorObjectMeta* metas) {
        Queue queue(8);
        ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
            return rawstor_target_meta(
                queue, target.c_str(), metas, 3, cb, data
            );
        });
        return res >= 0;
    };
    auto print_meta = [&](const char* when, const RawstorObjectMeta* metas) {
        std::cerr << when << ":";
        for (int i = 0; i < 3; ++i) {
            std::cerr << " [" << i << " " << names[metas[i].state]
                      << " w=" << metas[i].writers << "]";
        }
        std::cerr << std::endl;
    };

    // Outages are over: with the writers still going, the members must
    // settle (no copy left LOST, none unreachable) within a minute.
    RawstorObjectMeta metas[3]{};
    bool settled = false;
    for (int i = 0; i < 60 && !settled; ++i) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
        if (!read_meta(metas)) {
            continue;
        }
        settled = true;
        for (int m = 0; m < 3; ++m) {
            if (metas[m].state == RAWSTOR_OBJECT_SYNC_STATE_LOST ||
                metas[m].state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
                settled = false;
            }
        }
    }
    print_meta("after outages", metas);
    EXPECT_TRUE(settled) << "members did not settle";

    finish_writers();
    watching = false;
    watchdog.join();
    EXPECT_EQ(verify_failures, 0u)
        << "reads returned data that was not written";
    {
        // Every writer closed cleanly and the members settled: the two
        // copies must be the same bytes.
        std::ifstream a(arms[0]->data_path(uuid), std::ios::binary);
        std::ifstream b(arms[1]->data_path(uuid), std::ios::binary);
        std::vector<char> ba(4096), bb(4096);
        uint64_t differing = 0;
        for (uint64_t blk = 0; blk < size / 4096; ++blk) {
            a.read(ba.data(), 4096);
            b.read(bb.data(), 4096);
            if (ba != bb) {
                if (differing++ < 8) {
                    std::cerr << "COPIES differ at block " << blk << " (queue "
                              << blk / (size / 4096 / nqueues) << ")"
                              << std::endl;
                }
            }
        }
        std::cerr << "copies differ in " << differing << " blocks" << std::endl;
        EXPECT_EQ(differing, 0u) << "the members hold different data";
    }
    ASSERT_TRUE(read_meta(metas));
    print_meta("after close", metas);
    for (int m = 0; m < 3; ++m) {
        EXPECT_EQ(metas[m].state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN)
            << "member " << m;
    }
    EXPECT_EQ(dead_windows, 0u) << "writes did not resume after an outage";
    std::cerr << "writes=" << writes << " failures=" << failures << std::endl;
    for (int e = 0; e < 256; ++e) {
        if (errors[e] != 0) {
            std::cerr << "  errno " << e << " (" << strerror(e)
                      << "): " << errors[e] << std::endl;
        }
    }
    std::cerr << "ok per second:";
    for (unsigned int i = 0; i < std::min(seconds + 3, counters); ++i) {
        std::cerr << " " << ok_per_sec[i];
    }
    std::cerr << std::endl;
}
