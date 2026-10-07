#include "rawio_sync.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <atomic>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

/*
 * Several writers of one mirrored object (docs/multiattach.md): every
 * virtqueue of a multiqueue rawstor-vhost/rawstor-vduse device opens the
 * object on its own rawio queue and thread.
 */

namespace {

namespace fs = std::filesystem;

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
    Queue(unsigned int size) : _queue(nullptr) {
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

ssize_t target_create(
    Queue& queue, const std::string& target, const RawstorObjectSpec& spec
) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_create(queue, target.c_str(), &spec, cb, data);
    });
}

ssize_t
target_open(Queue& queue, const std::string& target, RawstorObject** object) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_open(queue, target.c_str(), 0, object, cb, data);
    });
}

ssize_t
target_meta(Queue& queue, const std::string& target, RawstorObjectMeta* meta) {
    ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_meta(queue, target.c_str(), 0, meta, 1, cb, data);
    });
    return res < 0 ? res : 0;
}

// `target` names exactly one member, so that member is index 0.
ssize_t target_set_sync_state(
    Queue& queue, const std::string& target,
    const RawstorObjectSyncState& sync_state
) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_set_member_sync_state(
            queue, target.c_str(), 0, 0, &sync_state, cb, data
        );
    });
}

ssize_t object_close(Queue& queue, RawstorObject* object) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_object_close(object, cb, data);
    });
}

int object_write(
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

class Members {
private:
    std::vector<fs::path> _dirs;
    std::string _uuid;

public:
    Members(size_t n, const std::string& uuid) : _uuid(uuid) {
        for (size_t i = 0; i < n; ++i) {
            std::ostringstream oss;
            oss << "test_multiattach_arm" << i;
            fs::path dir = fs::temp_directory_path() / oss.str();
            fs::remove_all(dir);
            _dirs.push_back(dir);
        }
    }

    ~Members() {
        for (const fs::path& dir : _dirs) {
            std::error_code ec;
            fs::remove_all(dir, ec);
        }
    }

    std::string target(size_t i) const {
        return "file://" + (_dirs[i] / _uuid).string();
    }

    std::string target_all() const {
        std::string ret;
        for (size_t i = 0; i < _dirs.size(); ++i) {
            if (i != 0) {
                ret += ",";
            }
            ret += target(i);
        }
        return ret;
    }

    void drop(size_t i) const { fs::remove_all(_dirs[i]); }

    // The first `size` bytes of member i's copy of chunk 0.
    std::string data(size_t i, size_t size) const {
        std::ifstream f(_dirs[i] / _uuid / "0" / "data", std::ios::binary);
        std::string ret(size, '\0');
        f.read(ret.data(), static_cast<std::streamsize>(size));
        return ret;
    }

    // A disk that comes back later with the contents it had when saved.
    void save(size_t i) const {
        fs::path bak = _dirs[i].string() + ".bak";
        fs::remove_all(bak);
        fs::copy(_dirs[i], bak, fs::copy_options::recursive);
    }

    void restore(size_t i) const {
        fs::path bak = _dirs[i].string() + ".bak";
        fs::remove_all(_dirs[i]);
        fs::rename(bak, _dirs[i]);
    }
};

RawstorObjectSpec spec_n(unsigned int width) {
    return RawstorObjectSpec{
        .size = 1ull << 20,
        .width = width,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
}

} // unnamed namespace

/*
 * One writer closing while another still writes must not mark the copies
 * CLEAN: a crash of the remaining writer would then go unnoticed at the
 * next open (docs/mirroring.md, case F5).
 */
TEST(MultiattachTest, close_of_one_writer_keeps_copies_dirty) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000c1");
    ASSERT_EQ(target_create(queue, members.target_all(), spec_n(2)), 0);

    RawstorObject* q0 = nullptr;
    RawstorObject* q1 = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &q0), 0);
    ASSERT_EQ(target_open(queue, members.target_all(), &q1), 0);

    std::string ping = "ping";
    ASSERT_EQ(object_write(queue, q0, ping.data(), ping.size(), 0), 0);
    ASSERT_EQ(object_write(queue, q1, ping.data(), ping.size(), 4096), 0);

    ASSERT_EQ(object_close(queue, q0), 0);

    for (size_t i = 0; i < 2; ++i) {
        RawstorObjectMeta m{};
        ASSERT_EQ(target_meta(queue, members.target(i), &m), 0);
        EXPECT_EQ(m.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY)
            << "member " << i;
    }

    ASSERT_EQ(object_close(queue, q1), 0);

    for (size_t i = 0; i < 2; ++i) {
        RawstorObjectMeta m{};
        ASSERT_EQ(target_meta(queue, members.target(i), &m), 0);
        EXPECT_EQ(m.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN)
            << "member " << i;
    }
}

/*
 * A degraded open makes the first write move the survivors to a fresh
 * sync_id. Every writer of the object must end up in that one sync set,
 * not each in its own.
 */
TEST(MultiattachTest, degraded_first_writes_share_one_sync_set) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000c2");
    ASSERT_EQ(target_create(queue, members.target_all(), spec_n(3)), 0);
    members.drop(2);

    RawstorObject* q0 = nullptr;
    RawstorObject* q1 = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &q0), 0);
    ASSERT_EQ(target_open(queue, members.target_all(), &q1), 0);

    std::string ping = "ping";
    ASSERT_EQ(object_write(queue, q0, ping.data(), ping.size(), 0), 0);
    ASSERT_EQ(object_write(queue, q1, ping.data(), ping.size(), 4096), 0);

    // q0 closes first: its CLEAN mark must not record a sync set q1 is
    // not part of, and q1's own close must leave both survivors on one.
    ASSERT_EQ(object_close(queue, q0), 0);
    ASSERT_EQ(object_close(queue, q1), 0);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.sync_state.sync_id, b.sync_state.sync_id);
    EXPECT_EQ(a.sync_state.epoch, 1u);
    EXPECT_EQ(b.sync_state.epoch, 1u);

    RawstorObject* again = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &again), 0);
    ASSERT_EQ(object_close(queue, again), 0);
}

/*
 * The multiqueue shape itself: every writer on its own thread and queue,
 * opening, writing and closing concurrently, round after round. Every
 * round must leave an object the next open accepts.
 */
TEST(MultiattachTest, concurrent_queues_degraded_rounds) {
    Members members(3, "00000000-0000-7000-8000-0000000000c3");
    {
        Queue queue(16);
        ASSERT_EQ(target_create(queue, members.target_all(), spec_n(3)), 0);
    }
    members.drop(2);

    const size_t nthreads = 4;
    const int rounds = 30;
    std::string target = members.target_all();

    for (int round = 0; round < rounds; ++round) {
        std::atomic<int> failures{0};
        std::vector<std::thread> threads;
        for (size_t t = 0; t < nthreads; ++t) {
            threads.emplace_back([&, t]() {
                Queue queue(16);
                RawstorObject* object = nullptr;
                if (target_open(queue, target, &object) != 0) {
                    ++failures;
                    return;
                }
                std::string buf(4096, static_cast<char>('a' + t));
                for (int i = 0; i < 8; ++i) {
                    if (object_write(
                            queue, object, buf.data(), buf.size(),
                            (t * 8 + i) * 4096
                        ) != 0) {
                        ++failures;
                    }
                }
                if (object_close(queue, object) != 0) {
                    ++failures;
                }
            });
        }
        for (std::thread& th : threads) {
            th.join();
        }
        ASSERT_EQ(failures.load(), 0) << "round " << round;

        Queue queue(16);
        RawstorObject* again = nullptr;
        ASSERT_EQ(target_open(queue, target, &again), 0) << "round " << round;
        ASSERT_EQ(object_close(queue, again), 0);
    }
}

/*
 * A member one writer cannot reach is excluded for every writer of the
 * process, and the exclusion is recorded: once that member comes back
 * with what it held before, it must read as an ancestor of the
 * survivors' sync set, not as a peer that silently missed later writes.
 */
TEST(MultiattachTest, member_lost_by_one_writer_excluded_for_all) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000c4");
    ASSERT_EQ(target_create(queue, members.target_all(), spec_n(3)), 0);

    RawstorObject* q0 = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &q0), 0);
    std::string a(4096, 'a');
    ASSERT_EQ(object_write(queue, q0, a.data(), a.size(), 0), 0);

    RawstorObjectMeta before{};
    ASSERT_EQ(target_meta(queue, members.target(2), &before), 0);
    ASSERT_NE(before.sync_state.sync_id, 0u);

    members.save(2);
    members.drop(2);

    RawstorObject* q1 = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &q1), 0);

    std::string b(4096, 'b');
    std::string c(4096, 'c');
    ASSERT_EQ(object_write(queue, q1, b.data(), b.size(), 4096), 0);
    ASSERT_EQ(object_write(queue, q0, c.data(), c.size(), 8192), 0);

    ASSERT_EQ(object_close(queue, q1), 0);
    ASSERT_EQ(object_close(queue, q0), 0);

    members.restore(2);

    RawstorObjectMeta m0{};
    RawstorObjectMeta m1{};
    ASSERT_EQ(target_meta(queue, members.target(0), &m0), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &m1), 0);
    EXPECT_EQ(m0.sync_state.sync_id, m1.sync_state.sync_id);
    EXPECT_NE(m0.sync_state.sync_id, before.sync_state.sync_id);
    bool ancestor = false;
    for (uint64_t h : m0.sync_state.sync_id_history) {
        ancestor = ancestor || h == before.sync_state.sync_id;
    }
    EXPECT_TRUE(ancestor);
}

/*
 * A member unreachable when the process opens the object is an exclusion
 * the dirty gate must record with a new sync_id -- also when the first
 * write comes from a writer that adopted the open instead of reconciling
 * the members itself. Otherwise the member, back with the sync_id it had,
 * reads as current next to copies that hold writes it never got.
 */
TEST(MultiattachTest, degraded_open_recorded_by_adopting_writer) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000c5");
    ASSERT_EQ(target_create(queue, members.target_all(), spec_n(3)), 0);

    // An established, nonzero sync set first: a legacy one (sync_id 0)
    // gets a new sync_id regardless.
    RawstorObject* first = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &first), 0);
    std::string a(4096, 'a');
    ASSERT_EQ(object_write(queue, first, a.data(), a.size(), 0), 0);
    ASSERT_EQ(object_close(queue, first), 0);

    RawstorObjectMeta before{};
    ASSERT_EQ(target_meta(queue, members.target(2), &before), 0);
    ASSERT_NE(before.sync_state.sync_id, 0u);

    members.save(2);
    members.drop(2);

    RawstorObject* q0 = nullptr;
    RawstorObject* q1 = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &q0), 0);
    ASSERT_EQ(target_open(queue, members.target_all(), &q1), 0);

    std::string b(4096, 'b');
    ASSERT_EQ(object_write(queue, q1, b.data(), b.size(), 4096), 0);

    ASSERT_EQ(object_close(queue, q1), 0);
    ASSERT_EQ(object_close(queue, q0), 0);

    members.restore(2);

    RawstorObjectMeta m0{};
    ASSERT_EQ(target_meta(queue, members.target(0), &m0), 0);
    EXPECT_NE(m0.sync_state.sync_id, before.sync_state.sync_id);
    bool ancestor = false;
    for (uint64_t h : m0.sync_state.sync_id_history) {
        ancestor = ancestor || h == before.sync_state.sync_id;
    }
    EXPECT_TRUE(ancestor);
}

/*
 * An online resync of a stale member while several queues of the process
 * write to the object: every queue duplicates its writes onto the member,
 * the sweeper never overwrites them with older data, and the member
 * rejoins byte-identical to the in-sync copy.
 */
TEST(MultiattachTest, resync_while_queues_write) {
    Members members(2, "00000000-0000-7000-8000-0000000000c7");
    const size_t size = 16ull << 20;
    {
        Queue queue(16);
        RawstorObjectSpec spec = spec_n(2);
        spec.size = size;
        ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

        // Member 1 is one sync set behind member 0, holding other data.
        RawstorObjectSyncState fresh{};
        fresh.epoch = 2;
        fresh.sync_id = 0x1111111111111111ull;
        fresh.sync_id_history[0] = 0x2222222222222222ull;
        fresh.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
        ASSERT_EQ(target_set_sync_state(queue, members.target(0), fresh), 0);
        RawstorObjectSyncState stale{};
        stale.epoch = 1;
        stale.sync_id = 0x2222222222222222ull;
        stale.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
        ASSERT_EQ(target_set_sync_state(queue, members.target(1), stale), 0);

        for (size_t i = 0; i < 2; ++i) {
            RawstorObject* member = nullptr;
            ASSERT_EQ(target_open(queue, members.target(i), &member), 0);
            std::string garbage(1 << 20, static_cast<char>('0' + i));
            for (uint64_t off = 0; off < size; off += garbage.size()) {
                ASSERT_EQ(
                    object_write(
                        queue, member, garbage.data(), garbage.size(), off
                    ),
                    0
                );
            }
            ASSERT_EQ(object_close(queue, member), 0);
        }
    }

    const size_t nthreads = 3;
    std::string target = members.target_all();
    std::atomic<bool> synced{false};
    std::atomic<int> failures{0};

    testing::internal::CaptureStderr();
    std::vector<std::thread> threads;
    for (size_t t = 0; t < nthreads; ++t) {
        threads.emplace_back([&, t]() {
            Queue queue(16);
            RawstorObject* object = nullptr;
            if (target_open(queue, target, &object) != 0) {
                ++failures;
                return;
            }
            std::string block(16 << 10, '\0');
            uint64_t seed = 0x9e3779b97f4a7c15ull * (t + 1);
            for (int i = 0; i < 200000 && !synced; ++i) {
                seed = seed * 6364136223846793005ull + 1442695040888963407ull;
                // Each queue its own blocks: overlapping in-flight writes of
                // different queues leave their region unspecified.
                uint64_t blocks = size / block.size() / nthreads;
                uint64_t off =
                    ((seed >> 33) % blocks * nthreads + t) * block.size();
                memset(
                    block.data(), 'a' + (int)((seed >> 20) % 26), block.size()
                );
                if (object_write(
                        queue, object, block.data(), block.size(), off
                    ) != 0) {
                    ++failures;
                    break;
                }
                if (t == 0 && i % 64 == 0) {
                    RawstorObjectMeta a{};
                    RawstorObjectMeta b{};
                    if (target_meta(queue, members.target(0), &a) == 0 &&
                        target_meta(queue, members.target(1), &b) == 0 &&
                        b.sync_state.state !=
                            RAWSTOR_OBJECT_SYNC_STATE_SYNCING &&
                        b.sync_state.sync_id == a.sync_state.sync_id) {
                        synced = true;
                    }
                }
            }
            // The member got its final state; the commit lets it join once
            // no write is in flight, run by the owner's queue: keep every
            // queue turning for a while before closing (closing the owner
            // ends the resync).
            for (int k = 0; k < 20; ++k) {
                rawio_wait_timeout(queue, 10);
            }
            if (object_close(queue, object) != 0) {
                ++failures;
            }
        });
    }
    for (std::thread& th : threads) {
        th.join();
    }
    std::string log = testing::internal::GetCapturedStderr();

    ASSERT_EQ(failures.load(), 0);
    EXPECT_TRUE(synced);
    EXPECT_NE(log.find("rejoined the set"), std::string::npos);
    EXPECT_EQ(log.find("Mirror resync aborted"), std::string::npos);
    EXPECT_TRUE(members.data(0, size) == members.data(1, size));
}
