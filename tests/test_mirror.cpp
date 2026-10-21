#include "opts.h"
#include "rawio_sync.hpp"
#include "register.hpp"
#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
#include <set>
#include <sstream>
#include <string>
#include <vector>

namespace {

namespace fs = std::filesystem;

int callback(size_t result, int error, void* data) {
    std::unique_ptr<std::function<void(size_t, int)>> cb(
        static_cast<std::function<void(size_t, int)>*>(data)
    );
    try {
        (*cb)(result, error);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
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

// Every control-plane operation (create/open/meta/set_sync_state/close) is
// queue-driven now (see ChangeLog.md's rawstor_target_*() migration) --
// these mirror tests/rawio_sync.hpp's own sync_run() usage pattern,
// already established by test_lifecycle.cpp's target_*() helpers.
ssize_t target_create(
    Queue& queue, const std::string& target, const RawstorObjectSpec& spec
) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_create(queue, target.c_str(), &spec, cb, data);
    });
}

ssize_t target_open(
    Queue& queue, const std::string& target, RawstorObject** object,
    int flags = 0
) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_open(
            queue, target.c_str(), flags, object, cb, data
        );
    });
}

// rawstor_target_meta() now takes an array (one entry per URI of the
// chunk at `offset`) instead of a single out-parameter -- every call
// site here queries a single-URI, single-chunk target at offset 0, so
// this keeps their own signature (one RawstorObjectMeta* out-parameter)
// by unwrapping that one entry.
ssize_t
target_meta(Queue& queue, const std::string& target, RawstorObjectMeta* meta) {
    ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_meta(queue, target.c_str(), meta, 1, cb, data);
    });
    if (res < 0) {
        return res;
    }
    return meta->state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE ? -ENOTCONN : 0;
}

// Every call site here passes a Members::target(i) -- a single-URI
// target naming exactly one mirror member -- so that member is always
// index 0.
ssize_t target_set_config(
    Queue& queue, const std::string& target,
    const RawstorObjectConfig& sync_state
) {
    // A ballot above every one the member holds.
    RawstorObjectMeta meta{};
    ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_meta(queue, target.c_str(), &meta, 1, cb, data);
    });
    if (res < 0) {
        return res;
    }
    RawstorObjectBallot ballot{
        std::max(meta.promised.counter, meta.accepted.counter) + 1, 7
    };
    RawstorObjectBallot next{0, 0};
    res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_sync_accept(
            queue, target.c_str(), 0, &ballot, &next, &sync_state, &meta, cb,
            data
        );
    });
    return res < 0 ? res : (res == 1 ? 0 : -EAGAIN);
}

ssize_t object_close(Queue& queue, RawstorObject* object) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_object_close(object, cb, data);
    });
}

/*
 * File-backed mirror members in per-member temp directories, sharing one UUID.
 */
class Members {
private:
    std::vector<fs::path> _dirs;
    std::string _uuid;

public:
    Members(size_t n, const std::string& uuid) : _uuid(uuid) {
        for (size_t i = 0; i < n; ++i) {
            std::ostringstream oss;
            oss << "test_mirror_arm" << i;
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
        std::ostringstream oss;
        oss << "file://" << (_dirs[i] / _uuid).string();
        return oss.str();
    }

    std::string target_all() const {
        std::ostringstream oss;
        for (size_t i = 0; i < _dirs.size(); ++i) {
            if (i != 0) {
                oss << ",";
            }
            oss << target(i);
        }
        return oss.str();
    }

    // The whole location gone (e.g. an unmounted disk): the member is
    // unreachable.
    void drop(size_t i) const { fs::remove_all(_dirs[i]); }

    // Only this object's own copy gone, its location still there
    // (docs/mirroring.md, case F10).
    void drop_copy(size_t i) const { fs::remove_all(_dirs[i] / _uuid); }

    // file::Backend keeps one chunk directory per object,
    // <uuid>/<offset>/, holding a "data" file and a "meta" file
    // (see get_target_dir() in src/file_backend.cpp) -- every target
    // here is a plain, non-chunked object, offset 0.
    fs::path dat(size_t i) const { return _dirs[i] / _uuid / "0" / "data"; }
    fs::path meta(size_t i) const { return _dirs[i] / _uuid / "0" / "meta"; }
};

std::string read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
}

// Whether a member's record names any member syncing: a resync recorded
// there is still in progress.
bool any_syncing(const RawstorObjectConfig& config) {
    for (uint8_t i = 0; i < config.nroles; ++i) {
        if (config.roles[i] == RAWSTOR_OBJECT_MEMBER_SYNCING) {
            return true;
        }
    }
    return false;
}

void object_write(
    Queue& queue, RawstorObject* object, const void* buf, size_t size,
    uint64_t offset, int expected_error
) {
    bool completed = false;
    auto cb = std::make_unique<std::function<void(size_t, int)>>(
        [&completed, size, expected_error](size_t result, int error) {
            EXPECT_EQ(error, expected_error);
            if (!expected_error) {
                EXPECT_EQ(result, size);
            }
            completed = true;
        }
    );
    int res = rawstor_object_pwrite(
        object, buf, size, offset, false, callback, cb.get()
    );
    ASSERT_EQ(res, 0);
    cb.release();

    while (!completed) {
        queue.wait();
    }
}

void object_read(
    Queue& queue, RawstorObject* object, void* buf, size_t size, uint64_t offset
) {
    bool completed = false;
    auto cb = std::make_unique<std::function<void(size_t, int)>>(
        [&completed, size](size_t result, int error) {
            EXPECT_EQ(error, 0);
            EXPECT_EQ(result, size);
            completed = true;
        }
    );
    int res =
        rawstor_object_pread(object, buf, size, offset, callback, cb.get());
    ASSERT_EQ(res, 0);
    cb.release();

    while (!completed) {
        queue.wait();
    }
}

// The single rawstor_object_close() now performs a clean close for a
// mirrored, DIRTY object (flush + durable CLEAN mark) -- see
// Chunk::close()'s own doc comment; there's no separate "_async"
// variant to reach for anymore.
void object_close_clean(Queue& queue, RawstorObject* object) {
    ssize_t res = object_close(queue, object);
    EXPECT_EQ(res, 0);
}

// A single-member write, opened and closed via the same queue-driven
// rawstor_target_*() path as every other control-plane call here -- unlike
// the original commit, there's no synchronous rawstor_object_open() left to
// reach for.
void object_write_single(
    Queue& queue, const std::string& target, const void* buf, size_t size,
    uint64_t offset
) {
    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, target, &member), 0);
    object_write(queue, member, buf, size, offset, 0);
    EXPECT_EQ(object_close(queue, member), 0);
}

/*
 * Drives the queue until the member at `behind` reports the same established
 * sync set as the member at `fresh`. This checks the persisted configuration,
 * not completion of the background resync on the client.
 */
bool wait_member_config_synced(
    Queue& queue, const std::string& fresh, const std::string& behind,
    size_t member_index = 1
) {
    for (int i = 0; i < 3000; ++i) {
        rawio_wait_timeout(queue, 10);

        RawstorObjectMeta a{};
        RawstorObjectMeta b{};
        if (target_meta(queue, fresh, &a) != 0) {
            continue;
        }
        if (target_meta(queue, behind, &b) != 0) {
            continue;
        }
        // Config publication precedes clearing LOST. Wait for both
        // externally visible steps before treating the rejoin as complete.
        if (!any_syncing(b.config) &&
            (b.config.nroles == 0 ||
             (member_index < b.config.nroles &&
              b.config.roles[member_index] == RAWSTOR_OBJECT_MEMBER_IN_SYNC)) &&
            b.state != RAWSTOR_OBJECT_SYNC_STATE_LOST &&
            a.config.sync_id != 0 && b.config.sync_id == a.config.sync_id) {
            return true;
        }
    }
    return false;
}

TEST(MirrorQuorumTest, open_refused_without_quorum_n2) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a0");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    members.drop(1);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, members.target_all(), &object);
    EXPECT_EQ(res, -ENOTCONN);
    EXPECT_EQ(object, nullptr);
}

/*
 * F1/F3 (docs/mirroring.md): every mirror member unreachable at open() --
 * not just below quorum, none at all. docs/mirroring.md's own F3 row
 * claims "-EIO to the caller" for this case ("all mirrors failed"); the
 * code's actual open()-time error is -ENOTCONN, same family as
 * open_refused_without_quorum_n2 above and matching the doc's own summary
 * line ("open without quorum fails with -ENOTCONN") rather than F3's row.
 * -EIO is what an already-open object's next write gets instead, once
 * every member has gone stale with none left to record DIRTY on (see
 * MirrorOstTest.all_mirrors_stale_write_reports_eio).
 */
TEST(MirrorQuorumTest, all_mirrors_down_at_open_refused) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a9");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    members.drop(0);
    members.drop(1);
    members.drop(2);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, members.target_all(), &object);
    EXPECT_EQ(res, -ENOTCONN);
    EXPECT_EQ(object, nullptr);
}

// RAWSTOR_READONLY alone needs the same quorum as a writable open, and
// RAWSTOR_FORCE without it never lifts the requirement for a writable one.
TEST(MirrorQuorumTest, readonly_or_force_alone_needs_quorum_n2) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000b1");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.width = 2;
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    members.drop(1);

    for (int flags : {RAWSTOR_READONLY, RAWSTOR_FORCE}) {
        RawstorObject* object = nullptr;
        EXPECT_EQ(
            target_open(queue, members.target_all(), &object, flags), -ENOTCONN
        );
        EXPECT_EQ(object, nullptr);
    }
}

// RAWSTOR_FORCE | RAWSTOR_READONLY drops the quorum requirement: one
// reachable member of two is enough to read from, but nothing may write.
TEST(MirrorQuorumTest, force_readonly_open_without_quorum_n2) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000b0");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.width = 2;
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &writer), 0);
    std::string ping = "ping";
    object_write(queue, writer, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, writer);

    members.drop(1);

    RawstorObject* object = nullptr;
    ASSERT_EQ(
        target_open(
            queue, members.target_all(), &object,
            RAWSTOR_FORCE | RAWSTOR_READONLY
        ),
        0
    );

    std::string data(4, '\0');
    object_read(queue, object, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");

    object_write(queue, object, ping.data(), ping.size(), 0, EROFS);

    EXPECT_EQ(object_close(queue, object), 0);
}

TEST(MirrorQuorumTest, degraded_open_with_quorum_n3) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a1");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObjectMeta initial{};
    ASSERT_EQ(target_meta(queue, members.target(0), &initial), 0);

    members.drop(2);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    /* The survivors got a fresh sync set; both are CLEAN and identical. */
    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_NE(a.config.sync_id, 0u);
    EXPECT_EQ(a.config.sync_id, b.config.sync_id);
    EXPECT_NE(a.config.sync_id, initial.config.sync_id);
    EXPECT_EQ(a.config.epoch, initial.config.epoch + 1);
    EXPECT_EQ(b.config.epoch, initial.config.epoch + 1);

    /* Both survivors carry the data. */
    for (size_t i = 0; i < 2; ++i) {
        RawstorObject* member = nullptr;
        ASSERT_EQ(target_open(queue, members.target(i), &member), 0);
        std::string data(4, '\0');
        object_read(queue, member, data.data(), data.size(), 0);
        EXPECT_EQ(data, "ping");
        EXPECT_EQ(object_close(queue, member), 0);
    }
}

TEST(MirrorQuorumTest, stale_arm_resynced) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a2");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* Member 0 is one sync set ahead of member 1. */
    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);

    RawstorObjectConfig stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(1), stale), 0);

    /* Distinct content on the fresh member only. */
    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* The stale member is resynced online while the object is open. */
    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.config.sync_id, b.config.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    /* The rejoined member carries the fresh member's data now. */
    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

// Closing the object while the online resync is still copying, then
// destroying the queue: the sweeper's in-flight I/O must not outlive the
// members' Slots it was issued on. The interrupted copy stays untrusted
// and a later open resyncs it to the end.
TEST(MirrorResyncTest, close_during_resync) {
    Members members(3, "00000000-0000-7000-8000-0000000000a9");

    {
        Queue queue(16);
        RawstorObjectSpec spec{
            .size = 256ull << 20,
            .width = 3,
            .chunk_size = 0,
            .stripe_width = 0,
            .failure_domain = 0,
        };
        ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

        RawstorObjectConfig fresh{};
        fresh.epoch = 2;
        fresh.sync_id = 0x1111111111111111ull;
        fresh.sync_id_history[0] = 0x2222222222222222ull;
        ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
        ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);

        RawstorObjectConfig stale{};
        stale.epoch = 1;
        stale.sync_id = 0x2222222222222222ull;
        ASSERT_EQ(target_set_config(queue, members.target(1), stale), 0);

        std::string ping = "ping";
        object_write_single(
            queue, members.target(0), ping.data(), ping.size(), 0
        );
        object_write_single(
            queue, members.target(2), ping.data(), ping.size(), 0
        );
    }

    // The queue goes away right after each close: whatever I/O close()
    // left behind completes inside its destructor.
    for (int i = 0; i < 20; ++i) {
        Queue queue(16);
        RawstorObject* object = nullptr;
        ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
        EXPECT_EQ(object_close(queue, object), 0);

        // A resync the closing writer ran does not outlive it in the
        // register: no writer is left to duplicate onto the member for it.
        RawstorObjectMeta a{};
        ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
        EXPECT_EQ(a.config.resync_owner, 0u);
        if (a.config.nroles == 3) {
            EXPECT_NE(a.config.roles[1], RAWSTOR_OBJECT_MEMBER_SYNCING);
        }
    }

    Queue queue(16);

    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_NE(b.config.sync_id, 0x1111111111111111ull);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );
    object_close_clean(queue, object);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

// Resync copies all-zero blocks as write_zeroes() and the rest as data:
// both must leave the rejoined member byte-identical to the fresh one,
// even over a stale member holding garbage everywhere.
TEST(MirrorQuorumTest, stale_arm_resynced_zero_blocks) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000c0");

    const size_t size = 2ull << 20;
    RawstorObjectSpec spec{
        .size = size,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);

    RawstorObjectConfig stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(1), stale), 0);

    // Fresh: "ping" in the first block, the second block never written.
    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);
    // Stale: garbage over both blocks.
    std::string garbage(size, 'x');
    object_write_single(
        queue, members.target(1), garbage.data(), garbage.size(), 0
    );

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );
    object_close_clean(queue, object);

    std::string expected(size, '\0');
    memcpy(expected.data(), ping.data(), ping.size());

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(size, 'y');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_TRUE(data == expected);
    EXPECT_EQ(object_close(queue, member), 0);
}

TEST(MirrorQuorumTest, split_brain_refused) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a3");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* Disjoint histories sharing only a common ancestor. */
    RawstorObjectConfig a{};
    a.epoch = 2;
    a.sync_id = 0x1111111111111111ull;
    a.sync_id_history[0] = 0x3333333333333333ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), a), 0);

    RawstorObjectConfig b{};
    b.epoch = 2;
    b.sync_id = 0x2222222222222222ull;
    b.sync_id_history[0] = 0x3333333333333333ull;
    ASSERT_EQ(target_set_config(queue, members.target(1), b), 0);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, members.target_all(), &object);
    EXPECT_EQ(res, -ENOTRECOVERABLE);
    EXPECT_EQ(object, nullptr);
}

TEST(MirrorQuorumTest, all_dirty_same_sync_id_opens) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a4");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* Unclean shutdown: every copy DIRTY within the same sync set. */
    RawstorObjectConfig dirty{};
    dirty.epoch = 1;
    dirty.sync_id = 0x4444444444444444ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), dirty), 0);
    ASSERT_EQ(target_set_config(queue, members.target(1), dirty), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    /* Full membership, established sync set: no identity churn. */
    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.config.sync_id, dirty.sync_id);
    EXPECT_EQ(b.config.sync_id, dirty.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MirrorQuorumTest, syncing_arm_resynced) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a5");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObjectConfig established{};
    established.epoch = 1;
    established.sync_id = 0x5555555555555555ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), established), 0);
    ASSERT_EQ(target_set_config(queue, members.target(1), established), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), established), 0);

    /* An interrupted resync left the member's role syncing: untrusted. */
    RawstorObjectConfig syncing = established;
    syncing.nroles = 3;
    syncing.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    syncing.roles[1] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    syncing.roles[2] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    ASSERT_EQ(target_set_config(queue, members.target(1), syncing), 0);

    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);
    object_write_single(queue, members.target(2), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* The untrusted member is resynced from scratch. */
    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.config.sync_id, b.config.sync_id);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

TEST(MirrorQuorumTest, physical_shrink_does_not_change_logical_size) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000aa");
    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.width = 2;
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    fs::resize_file(members.dat(1), spec.size - 4096);
    RawstorObjectMeta meta{};
    ASSERT_EQ(target_meta(queue, members.target(1), &meta), 0);
    EXPECT_EQ(meta.spec.size, spec.size);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    object_close_clean(queue, object);
}

TEST(MirrorQuorumTest, truncated_first_member_reads_from_surviving_copy) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000af");
    RawstorObjectSpec spec{};
    spec.size = 8192;
    spec.width = 2;
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    object_write(queue, object, "tail", 4, 8188, 0);
    object_close_clean(queue, object);
    fs::resize_file(members.dat(0), 4096);
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    char data[4]{};
    object_read(queue, object, data, sizeof(data), 8188);
    EXPECT_EQ(std::string(data, sizeof(data)), "tail");
    object_close_clean(queue, object);
}

TEST(MirrorQuorumTest, physical_growth_does_not_change_logical_size) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000ae");
    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    spec.width = 2;
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    fs::resize_file(members.dat(1), 2 * spec.size);
    RawstorObjectMeta meta{};
    ASSERT_EQ(target_meta(queue, members.target(1), &meta), 0);
    EXPECT_EQ(meta.spec.size, spec.size);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    object_write(queue, object, "x", 1, spec.size, EINVAL);
    object_close_clean(queue, object);
}

// A write that starts while the rejoining member is getting its final
// state is duplicated onto that member and may still fail there after the
// final state lands. The member joins the set without waiting for it, but
// the write is not acknowledged before the member it missed is excluded
// again: here the write comes back short on it, which degrades the member
// once it has joined.
TEST(MirrorResyncTest, write_failing_on_rejoining_member_degrades_it) {
    struct ScopedOpts {
        ScopedOpts() {
            RawstorOpts opts{};
            // Keep the reconnect probe away from the scripted member.
            opts.mirror_probe_interval = 60000;
            rawstor_opts_initialize(&opts);
        }
        ~ScopedOpts() { rawstor_opts_initialize(nullptr); }
    } opts;

    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000ab");
    // Small enough for the test server to take the copy in one read.
    RawstorObjectSpec spec{
        .size = 4096,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);

    // The second member is a scripted OST holding a stale copy.
    rawstor::tests::Server server(8812, 256);
    RawstorFrameMetaPayload stale = {
        .size = spec.size,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 3,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 1,
                .sync_id = 0x2222222222222222ull,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };
    std::atomic<bool> final_state_sent(false);
    auto s = std::make_unique<rawstor::tests::Session>(server);
    s->cmd_meta(RAWSTOR_MAGIC, 0, 0, stale);
    s->cmd_set_object(RAWSTOR_MAGIC, 1, 0);
    s->cmd_meta(RAWSTOR_MAGIC, 2, 0, stale);
    // The SYNCING role is decided with the first change of the register:
    // a prepare and an accept.
    s->cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, stale);
    std::atomic<bool> syncing_sent(false);
    s->cmd_meta(RAWSTOR_MAGIC, 5, 0, stale);
    server.read(
        "SYNCING SYNC_ACCEPT <<<", sizeof(RawstorFrameSyncPropose),
        [&syncing_sent](const void*) { syncing_sent = true; }
    );
    // The member answers with the record it holds: it names the member
    // syncing, so the copy that follows is a RESYNC write.
    RawstorFrameMetaPayload syncing = stale;
    syncing.config.nroles = 3;
    syncing.config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    syncing.config.roles[1] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    syncing.config.roles[2] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    s->cmd_sync_response(
        RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 6, 0, true, syncing
    );

    std::string target =
        members.target(0) +
        ",ost://127.0.0.1:8812/00000000-0000-7000-8000-0000000000ab," +
        members.target(2);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);
    for (int i = 0; i < 1000 && !syncing_sent; ++i) {
        rawio_wait_timeout(queue, 10);
    }
    ASSERT_TRUE(syncing_sent);

    // The resync's decision recorded the set: the writes below need no dirty
    // barrier.
    // The copy of an empty chunk goes out as zeroes.
    s->cmd_write_zeroes(RAWSTOR_MAGIC, 7, spec.size);
    s->cmd_flush(RAWSTOR_MAGIC, 8, 0); // durable before it rejoins
    RawstorFrameMetaPayload final_meta = stale;
    final_meta.state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
    // The rejoin, answered only once the client's write is in.
    s->cmd_meta(RAWSTOR_MAGIC, 9, 0, stale);
    server.read(
        "rejoin SYNC_ACCEPT <<<", sizeof(RawstorFrameSyncPropose),
        [&final_state_sent, &final_meta](const void* data) {
            final_meta.config =
                static_cast<const RawstorFrameSyncPropose*>(data)
                    ->payload.config;
            final_state_sent = true;
        }
    );
    s->cmd_write_request(4096);
    s->cmd_sync_response(
        RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 10, 0, true, stale
    );
    for (int i = 0; i < 1000 && !final_state_sent; ++i) {
        rawio_wait_timeout(queue, 10);
    }
    ASSERT_TRUE(final_state_sent);

    testing::internal::CaptureStderr();
    bool written = false;
    auto cb = std::make_unique<std::function<void(size_t, int)>>(
        [&written](size_t result, int error) {
            EXPECT_EQ(error, 0);
            EXPECT_EQ(result, 4096u);
            written = true;
        }
    );
    std::string block(4096, 'W');
    ASSERT_EQ(
        rawstor_object_pwrite(
            object, block.data(), block.size(), 0, false, callback, cb.get()
        ),
        0
    );
    cb.release();
    // The final state lands while the write still waits on the member.
    for (int i = 0; i < 20; ++i) {
        rawio_wait_timeout(queue, 10);
    }
    EXPECT_FALSE(written);
    s->cmd_write_response(RAWSTOR_MAGIC, 11, 2048);
    for (int i = 0; i < 1000 && !written; ++i) {
        rawio_wait_timeout(queue, 10);
    }
    ASSERT_TRUE(written);
    std::string log = testing::internal::GetCapturedStderr();
    size_t rejoined = log.find("rejoined the set");
    ASSERT_NE(rejoined, std::string::npos) << log;
    EXPECT_NE(log.find("Mirror member degraded", rejoined), std::string::npos)
        << log;

    // The member is out of the set: the close touches only the current members.
    object_close_clean(queue, object);
}

// A member that refuses the decision which brings it back has not rejoined:
// it is excluded again, and the writers go on without it.
TEST(MirrorResyncTest, member_refusing_its_rejoin_is_excluded_again) {
    struct ScopedOpts {
        ScopedOpts() {
            RawstorOpts opts{};
            // Keep the reconnect probe away from the scripted member.
            opts.mirror_probe_interval = 60000;
            rawstor_opts_initialize(&opts);
        }
        ~ScopedOpts() { rawstor_opts_initialize(nullptr); }
    } opts;

    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000ac");
    RawstorObjectSpec spec{
        .size = 4096,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);

    // The second member is a scripted OST holding a stale copy.
    rawstor::tests::Server server(8813, 256);
    RawstorFrameMetaPayload stale = {
        .size = spec.size,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 3,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 1,
                .sync_id = 0x2222222222222222ull,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };
    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, stale);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, stale);
        // The SYNCING role: a prepare and an accept.
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, stale);
        // The member answers with the record it holds, which names it
        // syncing: the copy that follows is a RESYNC write.
        RawstorFrameMetaPayload syncing = stale;
        syncing.config.nroles = 3;
        syncing.config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
        syncing.config.roles[1] = RAWSTOR_OBJECT_MEMBER_SYNCING;
        syncing.config.roles[2] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
        s.cmd_meta(RAWSTOR_MAGIC, 5, 0, stale);
        s.cmd_sync_accept_request();
        s.cmd_sync_response(
            RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 6, 0, true, syncing
        );
        // The copy of an empty chunk goes out as zeroes, durable before the
        // member rejoins.
        s.cmd_write_zeroes(RAWSTOR_MAGIC, 7, spec.size);
        s.cmd_flush(RAWSTOR_MAGIC, 8, 0);
        // The rejoin is refused: the member holds a higher ballot.
        s.cmd_meta(RAWSTOR_MAGIC, 9, 0, stale);
        s.cmd_sync_accept_request();
        s.cmd_sync_response(
            RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 10, 0, false, stale
        );
    }

    std::string target =
        members.target(0) +
        ",ost://127.0.0.1:8813/00000000-0000-7000-8000-0000000000ac," +
        members.target(2);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    // The start moves the epoch to 3, the rejoin decision to 4 and the
    // exclusion of the member that did not take it to 5.
    bool excluded = false;
    for (int i = 0; i < 1000 && !excluded; ++i) {
        rawio_wait_timeout(queue, 10);
        RawstorObjectMeta meta{};
        if (target_meta(queue, members.target(0), &meta) != 0) {
            continue;
        }
        excluded = meta.config.epoch >= 5 && meta.config.nroles == 3 &&
                   meta.config.roles[1] == RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    }
    EXPECT_TRUE(excluded);

    std::string block(4096, 'W');
    object_write(queue, object, block.data(), block.size(), 0, 0);
    object_close_clean(queue, object);
}

// Another writer decides a new configuration (here: it excludes the third
// member) while this one has the object open. This writer's next write is
// refused for its old epoch; it takes the decision over and writes to the
// members the decision names, instead of excluding the members that refused.
TEST(MirrorQuorumTest, write_takes_over_another_writers_decision) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000d1");
    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    std::string first = "first";
    object_write(queue, object, first.data(), first.size(), 0, 0);

    // The decision of the other writer, on a majority of the members.
    RawstorObjectMeta before{};
    ASSERT_EQ(target_meta(queue, members.target(0), &before), 0);
    RawstorObjectConfig decided = before.config;
    ++decided.epoch;
    memmove(
        &decided.sync_id_history[1], decided.sync_id_history,
        (RAWSTOR_OBJECT_SYNC_ID_HISTORY - 1) * sizeof(uint64_t)
    );
    decided.sync_id_history[0] = decided.sync_id;
    decided.sync_id = 0x5151515151515151ull;
    ASSERT_EQ(decided.nroles, 3);
    decided.roles[2] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    ASSERT_EQ(target_set_config(queue, members.target(0), decided), 0);
    ASSERT_EQ(target_set_config(queue, members.target(1), decided), 0);

    testing::internal::CaptureStderr();
    std::string second = "second";
    object_write(queue, object, second.data(), second.size(), 16, 0);
    std::string log = testing::internal::GetCapturedStderr();
    EXPECT_EQ(log.find("Mirror member degraded"), std::string::npos) << log;

    // This writer made no decision of its own, and wrote to the members the
    // other writer's decision names.
    for (size_t i : {0, 1}) {
        RawstorObjectMeta meta{};
        ASSERT_EQ(target_meta(queue, members.target(i), &meta), 0);
        EXPECT_EQ(meta.config.epoch, decided.epoch) << i;
        EXPECT_EQ(meta.config.sync_id, decided.sync_id) << i;
        EXPECT_EQ(meta.config.roles[2], RAWSTOR_OBJECT_MEMBER_EXCLUDED) << i;
        EXPECT_EQ(read_file(members.dat(i)).substr(16, second.size()), second)
            << i;
    }
    // The excluded member keeps its record. The first attempt of the write
    // may have reached it before the refusals came; it is resynced anyway.
    RawstorObjectMeta third{};
    ASSERT_EQ(target_meta(queue, members.target(2), &third), 0);
    EXPECT_EQ(third.config.epoch, before.config.epoch);
    EXPECT_EQ(third.config.sync_id, before.config.sync_id);

    // The writes that follow need no second look at the register.
    std::string third_write = "third";
    object_write(queue, object, third_write.data(), third_write.size(), 32, 0);
    object_close_clean(queue, object);
}

// A member this writer is excluding stays excluded when another writer's
// decision names it in-sync: its writes failed here, and none may be
// acknowledged without it in the set. The exclusion is recorded on top of the
// decision.
TEST(MirrorQuorumTest, pending_exclusion_survives_another_writers_decision) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000d7");
    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    // The last member is a scripted OST that answers as the copy it
    // replaces, and fails the second write.
    RawstorObjectMeta replaced{};
    ASSERT_EQ(target_meta(queue, members.target(2), &replaced), 0);
    RawstorFrameMetaPayload meta{};
    ASSERT_EQ(rawstor_frame_meta_encode(&meta, &replaced), 0);

    const std::string first = "first";
    const std::string second = "second";
    std::atomic<bool> injected(false);
    RawstorObjectConfig decided{};
    rawstor::tests::Server server(8760, 256);
    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, meta);
        // The dirty gate of the first write: a prepare and an accept.
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, meta);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 5, 0, meta);
        s.cmd_write(RAWSTOR_MAGIC, 7, first.size());
        // The second write reaches this member once the other two have it.
        // Before the member fails it, another writer decides a configuration
        // that names every member in-sync, on the other two.
        server.read(
            "second WRITE <<<", sizeof(RawstorFrameIO) + second.size(),
            [&](const void*) {
                for (int i = 0; i < 5000; ++i) {
                    if (read_file(members.dat(0)).substr(16, second.size()) ==
                            second &&
                        read_file(members.dat(1)).substr(16, second.size()) ==
                            second) {
                        break;
                    }
                    usleep(1000);
                }
                Queue other(16);
                RawstorObjectMeta before{};
                if (target_meta(other, members.target(0), &before) != 0) {
                    return;
                }
                decided = before.config;
                ++decided.epoch;
                for (size_t i : {0, 1}) {
                    if (target_set_config(other, members.target(i), decided) !=
                        0) {
                        return;
                    }
                }
                injected = true;
            }
        );
        s.cmd_write_response(RAWSTOR_MAGIC, 8, -EINVAL);
    }

    std::string target =
        members.target(0) + "," + members.target(1) +
        ",ost://127.0.0.1:8760/00000000-0000-7000-8000-0000000000d7";
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);
    object_write(queue, object, first.data(), first.size(), 0, 0);
    object_write(queue, object, second.data(), second.size(), 16, 0);
    ASSERT_TRUE(injected);
    object_close_clean(queue, object);

    for (size_t i : {0, 1}) {
        RawstorObjectMeta recorded{};
        ASSERT_EQ(target_meta(queue, members.target(i), &recorded), 0);
        EXPECT_EQ(recorded.config.roles[2], RAWSTOR_OBJECT_MEMBER_EXCLUDED)
            << i;
        EXPECT_EQ(recorded.config.epoch, decided.epoch + 1) << i;
        EXPECT_NE(recorded.config.sync_id, decided.sync_id) << i;
    }
}

// A transition of this writer meets another writer's decision first: the
// dirty gate of its first write takes the decision over and records the set
// as it is decided, instead of replacing it with this writer's view of the
// chunk.
TEST(MirrorQuorumTest, dirty_gate_builds_on_another_writers_decision) {
    Queue queue(16);
    Members members(5, "00000000-0000-7000-8000-0000000000d2");
    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 5,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    // The other writer excludes the last member, deciding on a majority.
    RawstorObjectMeta before{};
    ASSERT_EQ(target_meta(queue, members.target(1), &before), 0);
    RawstorObjectConfig decided = before.config;
    ++decided.epoch;
    decided.sync_id_history[0] = decided.sync_id;
    decided.sync_id = 0x5252525252525252ull;
    ASSERT_EQ(decided.nroles, 5);
    decided.roles[4] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    for (size_t i : {1, 2, 3}) {
        ASSERT_EQ(target_set_config(queue, members.target(i), decided), 0);
    }

    std::string first = "first";
    object_write(queue, object, first.data(), first.size(), 0, 0);
    object_close_clean(queue, object);

    for (size_t i : {0, 1, 2, 3}) {
        RawstorObjectMeta meta{};
        ASSERT_EQ(target_meta(queue, members.target(i), &meta), 0);
        EXPECT_EQ(meta.config.epoch, decided.epoch) << i;
        EXPECT_EQ(meta.config.sync_id, decided.sync_id) << i;
        EXPECT_EQ(meta.config.roles[4], RAWSTOR_OBJECT_MEMBER_EXCLUDED) << i;
        EXPECT_EQ(meta.config.roles[i], RAWSTOR_OBJECT_MEMBER_IN_SYNC) << i;
    }
    RawstorObjectMeta last{};
    ASSERT_EQ(target_meta(queue, members.target(4), &last), 0);
    EXPECT_EQ(last.config.epoch, before.config.epoch);
}

// Another writer starts a resync onto the third member. This writer takes
// the decision over at its next write and duplicates its writes onto the
// member too, without a resync of its own to attach to.
TEST(MirrorResyncTest, write_duplicates_onto_another_writers_syncing_member) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000d3");
    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    std::string first = "first";
    object_write(queue, object, first.data(), first.size(), 0, 0);

    RawstorObjectMeta before{};
    ASSERT_EQ(target_meta(queue, members.target(0), &before), 0);
    RawstorObjectConfig decided = before.config;
    ++decided.epoch;
    decided.roles[2] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    decided.resync_owner = 0x77;
    for (size_t i : {0, 1, 2}) {
        ASSERT_EQ(target_set_config(queue, members.target(i), decided), 0);
    }

    std::string second = "second";
    object_write(queue, object, second.data(), second.size(), 16, 0);

    for (size_t i : {0, 1, 2}) {
        RawstorObjectMeta meta{};
        ASSERT_EQ(target_meta(queue, members.target(i), &meta), 0);
        EXPECT_EQ(meta.config.epoch, decided.epoch) << i;
        EXPECT_EQ(meta.config.roles[2], RAWSTOR_OBJECT_MEMBER_SYNCING) << i;
        EXPECT_EQ(read_file(members.dat(i)).substr(16, second.size()), second)
            << i;
    }
    object_close_clean(queue, object);
}

namespace {

struct ScopedLease {
    ScopedLease(unsigned int probe, unsigned int lease) {
        RawstorOpts opts{};
        opts.mirror_probe_interval = probe;
        opts.mirror_resync_lease = lease;
        rawstor_opts_initialize(&opts);
    }
    ~ScopedLease() { rawstor_opts_initialize(nullptr); }
};

// Another writer has started a resync onto the third member, and this one
// has taken it over with its next write.
struct ForeignResync {
    Queue queue;
    Members members;
    RawstorObject* object = nullptr;
    RawstorObjectConfig decided{};

    ForeignResync(const char* uuid) : queue(16), members(3, uuid) {}

    void start() {
        RawstorObjectSpec spec{
            .size = 1ull << 20,
            .width = 3,
            .chunk_size = 0,
            .stripe_width = 0,
            .failure_domain = 0,
        };
        ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
        ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
        std::string first = "first";
        object_write(queue, object, first.data(), first.size(), 0, 0);

        RawstorObjectMeta before{};
        ASSERT_EQ(target_meta(queue, members.target(0), &before), 0);
        decided = before.config;
        ++decided.epoch;
        decided.roles[2] = RAWSTOR_OBJECT_MEMBER_SYNCING;
        decided.resync_owner = 0x77;
        for (size_t i : {0, 1, 2}) {
            ASSERT_EQ(target_set_config(queue, members.target(i), decided), 0);
        }
        std::string second = "second";
        object_write(queue, object, second.data(), second.size(), 16, 0);
    }

    // The other writer's sign of life: the register decided anew.
    void renew() {
        for (size_t i : {0, 1}) {
            ASSERT_EQ(target_set_config(queue, members.target(i), decided), 0);
        }
    }

    bool excluded() {
        RawstorObjectMeta meta{};
        if (target_meta(queue, members.target(0), &meta) != 0) {
            return false;
        }
        return meta.config.roles[2] == RAWSTOR_OBJECT_MEMBER_EXCLUDED &&
               meta.config.resync_owner == 0 &&
               meta.config.epoch > decided.epoch;
    }

    bool wait_excluded(int tenths_of_a_second) {
        for (int i = 0; i < tenths_of_a_second * 10 && !excluded(); ++i) {
            rawio_wait_timeout(queue, 10);
        }
        return excluded();
    }
};

} // namespace

// The writer that runs a resync is gone: it never renews the register. Once
// the lease is over, a writer that duplicates onto the member for it
// excludes the member.
TEST(MirrorResyncTest, silent_foreign_resync_is_released_after_the_lease) {
    ScopedLease lease(50, 300);
    ForeignResync f("00000000-0000-7000-8000-0000000000d4");
    f.start();
    EXPECT_FALSE(f.excluded());
    EXPECT_TRUE(f.wait_excluded(50));

    // The writer goes on without the member.
    std::string third = "third";
    object_write(f.queue, f.object, third.data(), third.size(), 32, 0);
    object_close_clean(f.queue, f.object);
}

// A resync that renews itself within the lease is left alone.
TEST(MirrorResyncTest, renewed_foreign_resync_is_not_released) {
    ScopedLease lease(50, 300);
    ForeignResync f("00000000-0000-7000-8000-0000000000d5");
    f.start();
    for (int i = 0; i < 20; ++i) {
        f.renew();
        rawio_wait_timeout(f.queue, 50);
    }
    EXPECT_FALSE(f.excluded());
    EXPECT_TRUE(f.wait_excluded(50));
    object_close_clean(f.queue, f.object);
}

// The writer that runs a resync closes before it ends: the register is left
// without a resync nobody runs, and the member is excluded.
TEST(MirrorResyncTest, closing_the_writer_releases_its_resync) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000d6");
    RawstorObjectSpec spec{
        .size = 256ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);
    RawstorObjectConfig stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(1), stale), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    // The register names the member syncing, with this writer as the owner.
    RawstorObjectMeta meta{};
    bool running = false;
    for (int i = 0; i < 2000 && !running; ++i) {
        rawio_wait_timeout(queue, 1);
        running = target_meta(queue, members.target(0), &meta) == 0 &&
                  meta.config.nroles == 3 &&
                  meta.config.roles[1] == RAWSTOR_OBJECT_MEMBER_SYNCING &&
                  meta.config.resync_owner != 0;
    }
    ASSERT_TRUE(running);
    uint64_t epoch = meta.config.epoch;

    EXPECT_EQ(object_close(queue, object), 0);

    ASSERT_EQ(target_meta(queue, members.target(0), &meta), 0);
    EXPECT_EQ(meta.config.roles[1], RAWSTOR_OBJECT_MEMBER_EXCLUDED);
    EXPECT_EQ(meta.config.resync_owner, 0u);
    EXPECT_GT(meta.config.epoch, epoch);
}

// The writer that runs a resync renews the register on a timer of its own:
// a write to the member that takes longer than the lease does not make the
// other writers take the resync for dead.
TEST(MirrorResyncTest, resync_renews_the_register_while_a_write_is_pending) {
    ScopedLease lease(60000, 300);
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000d8");
    RawstorObjectSpec spec{
        .size = 4096,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);

    // The second member is a scripted OST holding a stale copy, which takes
    // three leases to answer the copy.
    rawstor::tests::Server server(8814, 256);
    RawstorFrameMetaPayload stale = {
        .size = spec.size,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 3,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 1,
                .sync_id = 0x2222222222222222ull,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };
    std::atomic<bool> answered(false);
    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, stale);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, stale);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, stale);
        RawstorFrameMetaPayload syncing = stale;
        syncing.config.nroles = 3;
        syncing.config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
        syncing.config.roles[1] = RAWSTOR_OBJECT_MEMBER_SYNCING;
        syncing.config.roles[2] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
        s.cmd_meta(RAWSTOR_MAGIC, 5, 0, stale);
        s.cmd_sync_accept_request();
        s.cmd_sync_response(
            RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 6, 0, true, syncing
        );
        server.read(
            "WRITE_ZEROES <<<", sizeof(RawstorFrameIO),
            [&answered](const void*) {
                usleep(900 * 1000);
                answered = true;
            }
        );
        s.cmd_write_zeroes_response(RAWSTOR_MAGIC, 7, spec.size);
        s.cmd_flush(RAWSTOR_MAGIC, 8, 0);
        // The rejoin is refused, which ends the test's resync.
        s.cmd_meta(RAWSTOR_MAGIC, 9, 0, stale);
        s.cmd_sync_accept_request();
        s.cmd_sync_response(
            RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 10, 0, false, stale
        );
    }

    std::string target =
        members.target(0) +
        ",ost://127.0.0.1:8814/00000000-0000-7000-8000-0000000000d8," +
        members.target(2);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    // While the member does not answer, the register keeps being decided.
    std::set<uint64_t> ballots;
    for (int i = 0; i < 500 && !answered; ++i) {
        rawio_wait_timeout(queue, 10);
        RawstorObjectMeta meta{};
        if (target_meta(queue, members.target(0), &meta) == 0 &&
            meta.config.nroles == 3 &&
            meta.config.roles[1] == RAWSTOR_OBJECT_MEMBER_SYNCING) {
            ballots.insert(meta.accepted.counter);
        }
    }
    EXPECT_TRUE(answered);
    EXPECT_GE(ballots.size(), 4u);

    for (int i = 0; i < 500; ++i) {
        rawio_wait_timeout(queue, 10);
        RawstorObjectMeta meta{};
        if (target_meta(queue, members.target(0), &meta) == 0 &&
            meta.config.roles[1] == RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            break;
        }
    }
    object_close_clean(queue, object);
}

// A resync whose register cannot be renewed for a whole lease ends: the
// other writers take it for dead by then and exclude the member, so the
// owner does not go on copying.
TEST(MirrorResyncTest, resync_ends_when_its_lease_cannot_be_renewed) {
    ScopedLease lease(60000, 200);
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000d9");
    RawstorObjectSpec spec{
        .size = 4096,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);
    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(1), fresh), 0);

    // The second member is in sync and scripted: it takes the start of the
    // resync and fails the next request, so the register cannot be decided
    // again.
    RawstorObjectMeta replaced{};
    ASSERT_EQ(target_meta(queue, members.target(1), &replaced), 0);
    RawstorFrameMetaPayload meta{};
    ASSERT_EQ(rawstor_frame_meta_encode(&meta, &replaced), 0);
    rawstor::tests::Server in_sync(8815, 256);
    {
        rawstor::tests::Session s(in_sync);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, meta);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, meta);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 5, 0, meta);
        s.cmd_meta(RAWSTOR_MAGIC, 7, 0, meta);
        s.cmd_sync_accept_request();
        s.cmd_sync_response(
            RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 8, -EINVAL, false, meta
        );
        // Whatever the close asks of it.
        s.cmd_flush(RAWSTOR_MAGIC, 9, 0);
        s.cmd_leave(RAWSTOR_MAGIC, 10, 0);
    }

    // The third member is the one brought back, and scripted too: it takes
    // many leases to answer the copy.
    rawstor::tests::Server syncing_server(8816, 256);
    RawstorFrameMetaPayload stale = meta;
    stale.config = {};
    stale.config.epoch = 1;
    stale.config.sync_id = 0x2222222222222222ull;
    RawstorFrameMetaPayload syncing = stale;
    syncing.config.nroles = 3;
    syncing.config.roles[0] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    syncing.config.roles[1] = RAWSTOR_OBJECT_MEMBER_IN_SYNC;
    syncing.config.roles[2] = RAWSTOR_OBJECT_MEMBER_SYNCING;
    {
        rawstor::tests::Session s(syncing_server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, stale);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, stale);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, stale);
        s.cmd_meta(RAWSTOR_MAGIC, 5, 0, stale);
        s.cmd_sync_accept_request();
        s.cmd_sync_response(
            RAWSTOR_CMD_SYNC_ACCEPT, RAWSTOR_MAGIC, 6, 0, true, syncing
        );
        syncing_server.read(
            "WRITE_ZEROES <<<", sizeof(RawstorFrameIO),
            [](const void*) { usleep(1500 * 1000); }
        );
        s.cmd_write_zeroes_response(RAWSTOR_MAGIC, 7, spec.size);
    }

    std::string target =
        members.target(0) +
        ",ost://127.0.0.1:8815/00000000-0000-7000-8000-0000000000d9," +
        "ost://127.0.0.1:8816/00000000-0000-7000-8000-0000000000d9";
    testing::internal::CaptureStderr();
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);
    // The copy keeps the queue busy: wait by the clock, not by the number of
    // times it is driven.
    const auto until =
        std::chrono::steady_clock::now() + std::chrono::milliseconds(1000);
    while (std::chrono::steady_clock::now() < until) {
        rawio_wait_timeout(queue, 10);
    }
    EXPECT_EQ(object_close(queue, object), 0);
    std::string log = testing::internal::GetCapturedStderr();
    EXPECT_NE(
        log.find("could not be renewed for a whole lease, ending the resync"),
        std::string::npos
    ) << log;
}

TEST(MirrorResyncTest, resync_under_concurrent_writes) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a7");

    const uint64_t size = 8ull << 20;
    RawstorObjectSpec spec{
        .size = size,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);

    RawstorObjectConfig stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(1), stale), 0);

    // An unclean writer left the stale copy LOST. A full resync must
    // remove that state after restoring its data.
    RawstorObject* stale_writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &stale_writer), 0);
    const std::string obsolete = "obsolete";
    object_write(queue, stale_writer, obsolete.data(), obsolete.size(), 0, 0);
    ASSERT_EQ(
        rawstor::tests::sync_run(
            queue,
            [&](auto cb, void* data) {
                return rawstor_object_abandon(stale_writer, cb, data);
            }
        ),
        0
    );
    RawstorObjectMeta behind{};
    ASSERT_EQ(target_meta(queue, members.target(1), &behind), 0);
    ASSERT_EQ(behind.state, RAWSTOR_OBJECT_SYNC_STATE_LOST);

    /* Pre-existing content on the fresh member across every chunk. */
    for (uint64_t off = 0; off < size; off += 1ull << 20) {
        std::string block(4096, 'S');
        object_write_single(
            queue, members.target(0), block.data(), block.size(), off
        );
        object_write_single(
            queue, members.target(2), block.data(), block.size(), off
        );
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* Client writes race the sweeper across the whole object. */
    for (int k = 0; k < 16; ++k) {
        std::string block(4096, (char)('A' + k));
        object_write(
            queue, object, block.data(), block.size(),
            (uint64_t)k * (size / 16) + 512, 0
        );
    }

    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );

    ASSERT_EQ(target_meta(queue, members.target(1), &behind), 0);
    EXPECT_EQ(behind.state, RAWSTOR_OBJECT_SYNC_STATE_DIRTY);
    object_close_clean(queue, object);

    /* Byte-for-byte identity after the rejoin. */
    EXPECT_EQ(read_file(members.dat(0)), read_file(members.dat(1)));

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.config.sync_id, b.config.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

// A writer that vanished leaves the copies LOST and possibly different.
// The next open keeps both in the set, so writes go on at once, and heals
// the second copy from the first; LOST goes away only afterwards.
TEST(MirrorResyncTest, vanished_writer_copies_healed_in_the_set) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000b0");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &writer), 0);
    const std::string acked = "acked";
    object_write(queue, writer, acked.data(), acked.size(), 0, 0);
    ASSERT_EQ(
        rawstor::tests::sync_run(
            queue,
            [&](auto cb, void* data) {
                return rawstor_object_abandon(writer, cb, data);
            }
        ),
        0
    );

    /* A write the vanished writer left on the second copy only. */
    const std::string unacked = "unacked";
    object_write_single(
        queue, members.target(1), unacked.data(), unacked.size(), 8192
    );
    ASSERT_NE(read_file(members.dat(0)), read_file(members.dat(1)));
    for (size_t i = 0; i < 2; ++i) {
        RawstorObjectMeta m{};
        ASSERT_EQ(target_meta(queue, members.target(i), &m), 0);
        ASSERT_EQ(m.state, RAWSTOR_OBJECT_SYNC_STATE_LOST) << "member " << i;
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    const std::string next = "next";
    object_write(queue, object, next.data(), next.size(), 4096, 0);

    bool healed = false;
    for (int i = 0; i < 3000 && !healed; ++i) {
        rawio_wait_timeout(queue, 10);
        healed = true;
        for (size_t k = 0; k < 2; ++k) {
            RawstorObjectMeta m{};
            healed &= target_meta(queue, members.target(k), &m) == 0 &&
                      m.state != RAWSTOR_OBJECT_SYNC_STATE_LOST;
        }
    }
    ASSERT_TRUE(healed);
    object_close_clean(queue, object);

    EXPECT_EQ(read_file(members.dat(0)), read_file(members.dat(1)));

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.config.sync_id, b.config.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

// Several copies to heal are healed one after another; LOST goes away
// only once all of them are equal to the first.
TEST(MirrorResyncTest, vanished_writer_all_other_copies_healed) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000b1");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &writer), 0);
    const std::string acked = "acked";
    object_write(queue, writer, acked.data(), acked.size(), 0, 0);
    ASSERT_EQ(
        rawstor::tests::sync_run(
            queue,
            [&](auto cb, void* data) {
                return rawstor_object_abandon(writer, cb, data);
            }
        ),
        0
    );

    for (size_t i = 1; i < 3; ++i) {
        const std::string unacked = "unacked" + std::to_string(i);
        object_write_single(
            queue, members.target(i), unacked.data(), unacked.size(), 4096 * i
        );
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    bool healed = false;
    for (int i = 0; i < 3000 && !healed; ++i) {
        rawio_wait_timeout(queue, 10);
        healed = true;
        for (size_t k = 0; k < 3; ++k) {
            RawstorObjectMeta m{};
            healed &= target_meta(queue, members.target(k), &m) == 0 &&
                      m.state != RAWSTOR_OBJECT_SYNC_STATE_LOST;
        }
    }
    ASSERT_TRUE(healed);
    object_close_clean(queue, object);

    EXPECT_EQ(read_file(members.dat(0)), read_file(members.dat(1)));
    EXPECT_EQ(read_file(members.dat(0)), read_file(members.dat(2)));
    for (size_t k = 0; k < 3; ++k) {
        RawstorObjectMeta m{};
        ASSERT_EQ(target_meta(queue, members.target(k), &m), 0);
        EXPECT_EQ(m.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN) << "member " << k;
    }
}

// The copy healed from is the first CLEAN one, not simply the first in
// the list: a LOST first copy is overwritten by the CLEAN second.
TEST(MirrorResyncTest, vanished_writer_heals_from_first_clean_copy) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000b2");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &writer), 0);
    const std::string acked = "acked";
    object_write(queue, writer, acked.data(), acked.size(), 0, 0);
    ASSERT_EQ(
        rawstor::tests::sync_run(
            queue,
            [&](auto cb, void* data) {
                return rawstor_object_abandon(writer, cb, data);
            }
        ),
        0
    );

    /* The second copy is made consistent by hand, the first is not. */
    RawstorObjectMeta second{};
    ASSERT_EQ(target_meta(queue, members.target(1), &second), 0);
    RawstorObjectConfig begin, end;
    rawstor::tests::heal_configs(second.config, 0, begin, end);
    ASSERT_EQ(target_set_config(queue, members.target(1), begin), 0);
    ASSERT_EQ(target_set_config(queue, members.target(1), end), 0);
    const std::string unacked = "unacked";
    object_write_single(
        queue, members.target(0), unacked.data(), unacked.size(), 8192
    );
    RawstorObjectMeta first{};
    ASSERT_EQ(target_meta(queue, members.target(0), &first), 0);
    ASSERT_EQ(first.state, RAWSTOR_OBJECT_SYNC_STATE_LOST);
    ASSERT_EQ(target_meta(queue, members.target(1), &second), 0);
    ASSERT_EQ(second.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    ASSERT_NE(read_file(members.dat(0)), read_file(members.dat(1)));

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    bool healed = false;
    for (int i = 0; i < 3000 && !healed; ++i) {
        rawio_wait_timeout(queue, 10);
        healed = target_meta(queue, members.target(0), &first) == 0 &&
                 first.state != RAWSTOR_OBJECT_SYNC_STATE_LOST;
    }
    ASSERT_TRUE(healed);
    object_close_clean(queue, object);

    EXPECT_EQ(read_file(members.dat(0)), read_file(members.dat(1)));
    std::string at_8192 = read_file(members.dat(0)).substr(8192, 7);
    EXPECT_NE(at_8192, unacked);
}

TEST(MirrorResyncTest, probe_rejoins_recreated_arm) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a8");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* The third member is lost entirely (disk gone). */
    members.drop(2);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);

    /* The member is reprovisioned empty; the probe picks it up and resyncs. */
    RawstorObjectSpec member_spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target(2), member_spec), 0);

    EXPECT_TRUE(wait_member_config_synced(
        queue, members.target(0), members.target(2), 2
    ));

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta c{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(2), &c), 0);
    EXPECT_EQ(a.config.sync_id, c.config.sync_id);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(2), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

// F10 (docs/mirroring.md): one member's copy is missing from a location
// that's still there -- with the other two a majority on their own,
// open() recreates it blank from a survivor's own spec, and online
// resync fills it back in.
TEST(MirrorQuorumTest, missing_copy_recreated_and_resynced) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000aa");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &writer), 0);
    std::string ping = "ping";
    object_write(queue, writer, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, writer);

    members.drop_copy(2);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    EXPECT_TRUE(wait_member_config_synced(
        queue, members.target(0), members.target(2), 2
    ));
    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta c{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(2), &c), 0);
    EXPECT_EQ(a.config.sync_id, c.config.sync_id);
    EXPECT_EQ(c.spec.size, spec.size);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(2), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

// A recreated blank copy never counts toward the quorum: with one copy
// missing and another unreachable, the lone survivor is not a majority,
// so nothing is recreated and the open fails -- the unreachable copy may
// hold writes the survivor never saw.
TEST(MirrorQuorumTest, recreated_copy_does_not_make_quorum) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000ad");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    members.drop_copy(1);
    members.drop(2);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, members.target_all(), &object);
    EXPECT_EQ(res, -ENOTCONN);
    EXPECT_EQ(object, nullptr);
    EXPECT_FALSE(fs::exists(members.dat(1)));
}

// Two copies, one missing: the survivor alone is not a majority, so the
// missing copy is not recreated automatically and the open fails. Once
// the copy is recreated by hand, the next open resyncs it from the
// survivor.
TEST(MirrorQuorumTest, two_way_missing_copy_recreated_by_hand) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000ae");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* writer = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &writer), 0);
    std::string ping = "ping";
    object_write(queue, writer, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, writer);

    members.drop_copy(1);

    RawstorObject* object = nullptr;
    EXPECT_EQ(target_open(queue, members.target_all(), &object), -ENOTCONN);
    EXPECT_EQ(object, nullptr);
    EXPECT_FALSE(fs::exists(members.dat(1)));

    ASSERT_EQ(target_create(queue, members.target(1), spec), 0);

    // An operator must choose the survivor and record that choice on
    // both members before automatic recovery may use the new copy.
    RawstorObjectMeta survivor{};
    ASSERT_EQ(target_meta(queue, members.target(0), &survivor), 0);
    auto resolved = survivor.config;
    ++resolved.epoch;
    resolved.roles[1] = RAWSTOR_OBJECT_MEMBER_EXCLUDED;
    ASSERT_EQ(target_set_config(queue, members.target(0), resolved), 0);
    ASSERT_EQ(target_set_config(queue, members.target(1), resolved), 0);

    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );
    object_close_clean(queue, object);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

// Every copy missing: nothing survives to vouch the chunk never held
// data, so nothing is recreated -- reported as missing (ENOENT), not as
// unreachable.
TEST(MirrorQuorumTest, all_copies_missing_not_recreated) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000ab");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    members.drop_copy(0);
    members.drop_copy(1);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, members.target_all(), &object);
    EXPECT_EQ(res, -ENOENT);
    EXPECT_EQ(object, nullptr);
    EXPECT_FALSE(fs::exists(members.dat(0)));
    EXPECT_FALSE(fs::exists(members.dat(1)));
}

// A read-only open writes nothing, so a missing copy stays missing: the
// open itself still succeeds off the survivor alone (no quorum needed).
TEST(MirrorQuorumTest, readonly_open_does_not_recreate_missing_copy) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000ac");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    members.drop_copy(1);

    RawstorObject* object = nullptr;
    ASSERT_EQ(
        target_open(
            queue, members.target_all(), &object,
            RAWSTOR_FORCE | RAWSTOR_READONLY
        ),
        0
    );
    EXPECT_EQ(object_close(queue, object), 0);
    EXPECT_FALSE(fs::exists(members.dat(1)));
}

TEST(MirrorQuorumTest, clean_close_stable_identity) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a6");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* First session establishes the sync set. */
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta first{};
    ASSERT_EQ(target_meta(queue, members.target(0), &first), 0);
    EXPECT_NE(first.config.sync_id, 0u);
    EXPECT_EQ(first.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    /* A healthy second session must not churn the identity. */
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta second{};
    ASSERT_EQ(target_meta(queue, members.target(0), &second), 0);
    EXPECT_EQ(second.config.sync_id, first.config.sync_id);
    EXPECT_EQ(second.config.epoch, first.config.epoch);
    EXPECT_EQ(second.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

/*
 * A stale member whose own ancestor sync_id already records its exclusion
 * does not change the membership: the first write keeps the identity.
 * Its rejoin does, exactly once.
 */
TEST(MirrorQuorumTest, stale_member_bumps_identity_on_rejoin_only) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000af");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObjectConfig fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(0), fresh), 0);
    ASSERT_EQ(target_set_config(queue, members.target(2), fresh), 0);

    RawstorObjectConfig stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    ASSERT_EQ(target_set_config(queue, members.target(1), stale), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);

    EXPECT_TRUE(
        wait_member_config_synced(queue, members.target(0), members.target(1))
    );
    object_close_clean(queue, object);

    RawstorObjectMeta am{};
    RawstorObjectMeta bm{};
    ASSERT_EQ(target_meta(queue, members.target(0), &am), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &bm), 0);
    EXPECT_EQ(am.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_NE(am.config.sync_id, fresh.sync_id);
    EXPECT_EQ(am.config.sync_id_history[0], fresh.sync_id);
    EXPECT_EQ(am.config.epoch, fresh.epoch + 2);
    EXPECT_EQ(bm.config.sync_id, am.config.sync_id);
    EXPECT_EQ(bm.config.epoch, am.config.epoch);
}

/*
 * An unreachable member may still carry the current sync_id: a degraded
 * open changes the membership, and the first write records it with a new
 * one.
 */
TEST(MirrorQuorumTest, degraded_open_changes_identity) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000b1");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta first{};
    ASSERT_EQ(target_meta(queue, members.target(0), &first), 0);
    ASSERT_NE(first.config.sync_id, 0u);

    members.drop(2);

    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta second{};
    ASSERT_EQ(target_meta(queue, members.target(0), &second), 0);
    EXPECT_NE(second.config.sync_id, first.config.sync_id);
    EXPECT_EQ(second.config.sync_id_history[0], first.config.sync_id);
    EXPECT_EQ(second.config.epoch, first.config.epoch + 1);
}

/*
 * OST mirror over two scripted servers: the first member fails the read with
 * a payload error, the second serves the data; the client then repairs the
 * region on the first member (dirty gate on both members + rewrite).
 */
TEST(MirrorOstTest, read_failover_and_repair) {
    Queue queue(16);
    rawstor::tests::Server server1(8753, 256);
    rawstor::tests::Server server2(8754, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-0000000000b0,"
        "ost://127.0.0.1:8754/00000000-0000-7000-8000-0000000000b0";

    RawstorFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 0,
                .sync_id = 0,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };

    /*
     * The object is CLEAN, so the connection layer still retries reads
     * transparently: the member serves the error on the initial session and
     * on two reopened ones before the read fails over to the second member.
     * An I/O error is no payload error, so nothing is repaired; the clean
     * close then leaves both members.
     */
    // Both members go through Slot::open()'s own combined SET_OBJECT+META
    // step (see its own comment), concurrently, on their first session --
    // Chunk::create()'s own overall spec comes straight out of that same
    // META answer (see its own comment), no separate round trip. Every
    // later low-level reconnect (_reconnect()) goes through
    // Backend::set_object() only, but it always folds its own META fetch
    // in on success too, so each reopened session below still gets its
    // own SET_OBJECT+META pair.
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read_error(RAWSTOR_MAGIC, 2, -EIO);
    }
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read_error(RAWSTOR_MAGIC, 2, -EIO);
    }
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read_error(RAWSTOR_MAGIC, 2, -EIO);
        s.cmd_leave(RAWSTOR_MAGIC, 3, 0);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read(RAWSTOR_MAGIC, 2, "pong", 4);
        s.cmd_leave(RAWSTOR_MAGIC, 3, 0);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string data(4, '\0');
    object_read(queue, object, data.data(), data.size(), 0);
    EXPECT_EQ(data, "pong");

    EXPECT_EQ(object_close(queue, object), 0);
}

/*
 * Losing one of two members freezes writes without acknowledging the
 * partial write; a subsequent write fails without touching the wire.
 */
TEST(MirrorOstTest, two_members_freeze_below_majority) {
    Queue queue(16);
    rawstor::tests::Server server1(8753, 256);
    rawstor::tests::Server server2(8754, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-0000000000b1,"
        "ost://127.0.0.1:8754/00000000-0000-7000-8000-0000000000b1";

    RawstorFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 0,
                .sync_id = 0,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 4, 0, legacy);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 6, -EIO);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 4, 0, legacy);
        s.cmd_write(RAWSTOR_MAGIC, 6, 4);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, EIO);
    object_write(queue, object, ping.data(), ping.size(), 8, EIO);

    EXPECT_EQ(object_close(queue, object), 0);
}

/*
 * F3 (docs/mirroring.md): open() succeeds while every member is still
 * reachable, but the first write's dirty barrier fans SET_SYNC_STATE out
 * to an empty set once both have already gone stale -- see
 * Chunk::_run_dirty_barrier()'s own `survivors == 0` check. The write
 * reports -EIO, matching the doc's own summary line ("writes ... with no
 * member left fail with -EIO") rather than F3's row (which conflates this
 * with the open()-time case -- see MirrorQuorumTest.
 * all_mirrors_down_at_open_refused above). A second write fails the same
 * way without even touching the wire: Chunk::_run_meta_fan_out() throws
 * -EIO immediately once it finds no IN_SYNC member to fan out to at all.
 *
 * The dirty-barrier failure is scripted as -EINVAL rather than -EIO:
 * Slot::_with_retry() treats -EIO as a transient, retryable failure
 * (reconnect + up to rawstor_opts_io_attempts() attempts, 3 under this
 * suite's own test override -- see tests/main.cpp), which would need 3
 * scripted reconnect sessions per member just to reach the same end
 * state. is_permanent_backend_error() (src/slot.cpp) treats
 * -EINVAL as non-retryable instead, so a single scripted response is
 * enough to reach "member excluded" -- the class of error is what this
 * test cares about, not this specific one.
 */
TEST(MirrorOstTest, all_mirrors_stale_write_reports_eio) {
    Queue queue(16);
    rawstor::tests::Server server1(8755, 256);
    rawstor::tests::Server server2(8756, 256);
    std::string target =
        "ost://127.0.0.1:8755/00000000-0000-7000-8000-0000000000b2,"
        "ost://127.0.0.1:8756/00000000-0000-7000-8000-0000000000b2";

    RawstorFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 0,
                .sync_id = 0,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        /* Both members reject the first write's dirty-barrier update. */
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 4, -EINVAL, legacy);
    }
    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 4, -EINVAL, legacy);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, EIO);
    /* Both members are now STALE in memory: the retry never reaches the
     * wire at all. */
    object_write(queue, object, ping.data(), ping.size(), 8, EIO);

    EXPECT_EQ(object_close(queue, object), 0);
}

/*
 * F6 (docs/mirroring.md): while DIRTY, a lost session might hide a
 * restarted backend that lost acknowledged writes from its page cache --
 * undetectable from metadata alone, so the conservative rule is to treat
 * any such member as STALE, even though this test's member0 answers every
 * attempt with a plain transport-class error (-EIO) rather than actually
 * restarting; Chunk::_read()'s own comment (case F6) draws the same
 * distinction this test exercises: an EIO (transport-class) failure while
 * DIRTY degrades the member durably, unlike an EPROTO (payload) failure,
 * which only triggers a read-repair of that one region.
 *
 * A single scripted failure is enough here, unlike
 * MirrorOstTest.read_failover_and_repair's own (CLEAN-object) member0
 * script, which needs 3 reconnect rounds to exhaust
 * Slot::_with_retry()'s transparent-retry budget:
 * Chunk::_run_dirty_barrier() turns transparent retry off for every
 * member the moment the object goes DIRTY (src/chunk.cpp, case F6's own
 * comment there), specifically so a transport failure surfaces
 * immediately instead of being silently retried once acknowledged writes
 * are on the line.
 */
TEST(MirrorOstTest, session_loss_while_dirty_excludes_member) {
    Queue queue(16);
    rawstor::tests::Server server1(8757, 256);
    rawstor::tests::Server server2(8758, 256);
    std::string target =
        "ost://127.0.0.1:8757/00000000-0000-7000-8000-0000000000b3,"
        "ost://127.0.0.1:8758/00000000-0000-7000-8000-0000000000b3";

    RawstorFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .member_role = RAWSTOR_MEMBER_DATA,
        .writers = 0,
        .config =
            {
                .epoch = 0,
                .sync_id = 0,
                .sync_id_history = {},
                .resync_owner = 0,
                .nroles = 0,
                .roles = {},
            },
        .promised = {},
        .accepted = {},
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 4, 0, legacy);
        s.cmd_write(RAWSTOR_MAGIC, 6, 4);
        /* member0's session is "lost" (a transport-class error, not a
         * payload one) right while the object is DIRTY; transparent retry
         * is already off by this point, so _read() moves on to member1
         * after this one failure. */
        s.cmd_read_error(RAWSTOR_MAGIC, 7, -EIO);
    }
    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 4, 0, legacy);
        s.cmd_write(RAWSTOR_MAGIC, 6, 4);
        s.cmd_read(RAWSTOR_MAGIC, 7, "ping", 4);
        /* A single survivor cannot record a majority transition. */
        s.cmd_flush(RAWSTOR_MAGIC, 8, 0);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);

    std::string data(4, '\0');
    object_read(queue, object, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");

    // No manual drain before closing: _degrade_detached() above started
    // eagerly and (unlike a plain transport hiccup) synchronously reaches
    // _meta_gate.begin() before _read() itself returns, so close()'s own
    // co_await _meta_gate.settle() already waits for its degrade barrier
    // to land -- an explicit drain here would only widen the window for
    // RAWSTOR_OPTS_MIRROR_PROBE_INTERVAL's reconnect probe (200ms under
    // this suite, tests/main.cpp) to race in and reconnect the now-STALE
    // member0, which nothing here has scripted for.
    EXPECT_EQ(object_close(queue, object), -EIO);
}

/*
 * A copy that cannot leave cleanly is not clean: LEAVE fails on one data
 * member, and the close touches nothing else on it. The other members left
 * on their own and are CLEAN, so the next open has a reference to heal the
 * member from (MirrorResyncTest.vanished_writer_heals_from_first_clean_copy);
 * that a session ending without LEAVE leaves its copy LOST is the copy's own
 * doing (MemberStateTest.abandoned_writer_loses_the_copy).
 */
TEST(MirrorOstTest, failed_leave_on_a_data_member_leaves_the_others_clean) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000b4");
    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
        .stripe_width = 0,
        .failure_domain = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    // The middle member is a scripted OST that answers as the copy it
    // replaces, so nothing sets it apart from the others.
    RawstorObjectMeta replaced{};
    ASSERT_EQ(target_meta(queue, members.target(1), &replaced), 0);
    RawstorFrameMetaPayload meta{};
    ASSERT_EQ(rawstor_frame_meta_encode(&meta, &replaced), 0);

    rawstor::tests::Server server(8759, 256);
    {
        rawstor::tests::Session s(server);
        s.cmd_meta(RAWSTOR_MAGIC, 0, 0, meta);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, meta);
        // The first write's dirty gate: a prepare and an accept.
        s.cmd_sync_prepare(RAWSTOR_MAGIC, 3, 0, meta);
        s.cmd_sync_accept(RAWSTOR_MAGIC, 5, 0, meta);
        s.cmd_write(RAWSTOR_MAGIC, 7, 4);
        // The close: a flush, then the departure that fails. Nothing
        // follows it.
        s.cmd_flush(RAWSTOR_MAGIC, 8, 0);
        s.cmd_leave(RAWSTOR_MAGIC, 9, -EIO);
    }

    std::string target =
        members.target(0) +
        ",ost://127.0.0.1:8759/00000000-0000-7000-8000-0000000000b4," +
        members.target(2);
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);
    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    for (size_t i : {0, 2}) {
        RawstorObjectMeta left{};
        ASSERT_EQ(target_meta(queue, members.target(i), &left), 0);
        EXPECT_EQ(left.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN) << i;
        EXPECT_EQ(left.writers, 0u) << i;
    }
}

} // unnamed namespace
