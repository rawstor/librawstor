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

#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <functional>
#include <future>
#include <iostream>
#include <memory>
#include <random>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

/*
 * Several writable opens of one mirrored object (one per virtqueue of
 * rawstor-vhost) keep writing while the OSTs holding its members stop and
 * come back: the resync of a returning member starts and ends under
 * concurrent writers.
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
        if (res < 0) {
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

unsigned int env_uint(const char* name, unsigned int fallback) {
    const char* v = getenv(name);
    return v != nullptr ? static_cast<unsigned int>(atoi(v)) : fallback;
}

} // unnamed namespace

TEST(ResyncStressTest, writers_survive_member_restarts) {
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
    std::atomic<unsigned long> ok_per_sec[4096] = {};
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
                failures += 1000000;
                return;
            }
            std::mt19937_64 rng(q + 1);
            std::vector<char> buf(512 << 10, static_cast<char>('a' + q));
            while (!stop) {
                size_t len = ((rng() % 128) + 1) * 4096;
                uint64_t off = (rng() % ((size - len) / 4096)) * 4096;
                int err = write_once(queue, object, buf.data(), len, off);
                writes += 1;
                if (err != 0) {
                    failures += 1;
                    errors[err & 255] += 1;
                } else {
                    auto sec = std::chrono::duration_cast<std::chrono::seconds>(
                                   std::chrono::steady_clock::now() - t0
                    )
                                   .count();
                    ok_per_sec[sec & 4095] += 1;
                }
            }
            rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
                return rawstor_object_close(object, cb, data);
            });
        });
    }

    std::mt19937_64 rng(12345);
    auto deadline =
        std::chrono::steady_clock::now() + std::chrono::seconds(seconds);
    const unsigned int settle_ms = env_uint("RAWSTOR_STRESS_SETTLE_MS", 6000);
    unsigned long ok_at_check = 0;
    unsigned int dead_windows = 0;
    while (std::chrono::steady_clock::now() < deadline) {
        unsigned int victim = static_cast<unsigned int>(rng() % 2);
        std::this_thread::sleep_for(
            std::chrono::milliseconds(300 + rng() % 1500)
        );
        std::cerr << "CHAOS stop arm " << victim << std::endl;
        arms[victim]->stop();
        std::this_thread::sleep_for(
            std::chrono::milliseconds(100 + rng() % 1500)
        );
        std::cerr << "CHAOS start arm " << victim << std::endl;
        arms[victim]->start();
        // One outage at a time: the returned member gets its resync before
        // the next one goes down, and writes must be going on again.
        std::this_thread::sleep_for(std::chrono::milliseconds(settle_ms));
        unsigned long ok_now = 0;
        for (int i = 0; i < 4096; ++i) {
            ok_now += ok_per_sec[i];
        }
        if (ok_now == ok_at_check) {
            ++dead_windows;
        }
        ok_at_check = ok_now;
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

    stop = true;
    for (auto& t : writers) {
        t.join();
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
    for (unsigned int i = 0; i < seconds + 3; ++i) {
        std::cerr << " " << ok_per_sec[i];
    }
    std::cerr << std::endl;
}
