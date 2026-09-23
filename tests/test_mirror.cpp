#include "rawio_sync.hpp"
#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <functional>
#include <memory>
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

ssize_t
target_open(Queue& queue, const std::string& target, RawstorObject** object) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_open(queue, target.c_str(), object, cb, data);
    });
}

// rawstor_target_meta() now takes an array (one entry per URI in
// `target`) instead of a single out-parameter -- every call site here
// queries a single-URI target, so this keeps their own signature (one
// RawstorObjectMeta* out-parameter) by unwrapping that one entry.
ssize_t
target_meta(Queue& queue, const std::string& target, RawstorObjectMeta* meta) {
    ssize_t res = rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_meta(queue, target.c_str(), meta, 1, cb, data);
    });
    if (res < 0) {
        return res;
    }
    return meta->sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE
               ? -ENOTCONN
               : 0;
}

ssize_t target_set_sync_state(
    Queue& queue, const std::string& target,
    const RawstorObjectSyncState& sync_state
) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_set_sync_state(
            queue, target.c_str(), &sync_state, cb, data
        );
    });
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

    void drop(size_t i) const { fs::remove_all(_dirs[i]); }

    // file::Backend keeps one chunk directory per object,
    // <uuid>/<offset>/, holding a "data" file and a "meta" file
    // (see get_target_dir() in src/file_backend.cpp) -- every target
    // here is a plain, non-chunked object, offset 0.
    fs::path dat(size_t i) const { return _dirs[i] / _uuid / "0" / "data"; }
};

std::string read_file(const fs::path& path) {
    std::ifstream f(path, std::ios::binary);
    std::ostringstream oss;
    oss << f.rdbuf();
    return oss.str();
}

void object_write(
    Queue& queue, RawstorObject* object, const void* buf, size_t size,
    off_t offset, int expected_error
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
    Queue& queue, RawstorObject* object, void* buf, size_t size, off_t offset
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
    off_t offset
) {
    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, target, &member), 0);
    object_write(queue, member, buf, size, offset, 0);
    EXPECT_EQ(object_close(queue, member), 0);
}

/*
 * Drives the queue until the member at `behind` reports the same established
 * sync set as the member at `fresh` (and is not mid-resync anymore).
 */
bool wait_member_synced(
    Queue& queue, const std::string& fresh, const std::string& behind
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
        if (b.sync_state.state != RAWSTOR_OBJECT_SYNC_STATE_SYNCING &&
            a.sync_state.sync_id != 0 &&
            b.sync_state.sync_id == a.sync_state.sync_id) {
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

TEST(MirrorQuorumTest, degraded_open_with_quorum_n3) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a1");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

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
    EXPECT_EQ(a.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_NE(a.sync_state.sync_id, 0u);
    EXPECT_EQ(a.sync_state.sync_id, b.sync_state.sync_id);
    EXPECT_EQ(a.sync_state.epoch, 1u);
    EXPECT_EQ(b.sync_state.epoch, 1u);

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
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* Member 0 is one sync set ahead of member 1. */
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

    /* Distinct content on the fresh member only. */
    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* The stale member is resynced online while the object is open. */
    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.sync_state.sync_id, b.sync_state.sync_id);
    EXPECT_EQ(a.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    /* The rejoined member carries the fresh member's data now. */
    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

TEST(MirrorQuorumTest, split_brain_refused) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a3");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* Disjoint histories sharing only a common ancestor. */
    RawstorObjectSyncState a{};
    a.epoch = 2;
    a.sync_id = 0x1111111111111111ull;
    a.sync_id_history[0] = 0x3333333333333333ull;
    a.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    ASSERT_EQ(target_set_sync_state(queue, members.target(0), a), 0);

    RawstorObjectSyncState b{};
    b.epoch = 2;
    b.sync_id = 0x2222222222222222ull;
    b.sync_id_history[0] = 0x3333333333333333ull;
    b.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    ASSERT_EQ(target_set_sync_state(queue, members.target(1), b), 0);

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
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* Unclean shutdown: every copy DIRTY within the same sync set. */
    RawstorObjectSyncState dirty{};
    dirty.epoch = 1;
    dirty.sync_id = 0x4444444444444444ull;
    dirty.state = RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
    ASSERT_EQ(target_set_sync_state(queue, members.target(0), dirty), 0);
    ASSERT_EQ(target_set_sync_state(queue, members.target(1), dirty), 0);

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
    EXPECT_EQ(a.sync_state.sync_id, dirty.sync_id);
    EXPECT_EQ(b.sync_state.sync_id, dirty.sync_id);
    EXPECT_EQ(a.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MirrorQuorumTest, syncing_arm_resynced) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a5");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    RawstorObjectSyncState established{};
    established.epoch = 1;
    established.sync_id = 0x5555555555555555ull;
    established.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    ASSERT_EQ(target_set_sync_state(queue, members.target(0), established), 0);
    ASSERT_EQ(target_set_sync_state(queue, members.target(1), established), 0);

    /* An interrupted resync left the member marked SYNCING: untrusted. */
    RawstorObjectSyncState syncing = established;
    syncing.state = RAWSTOR_OBJECT_SYNC_STATE_SYNCING;
    ASSERT_EQ(target_set_sync_state(queue, members.target(1), syncing), 0);

    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* The untrusted member is resynced from scratch. */
    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.sync_state.sync_id, b.sync_state.sync_id);
    EXPECT_EQ(b.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

TEST(MirrorQuorumTest, size_mismatch_smaller_member_excluded_and_resynced) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000aa");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

    /* An established sync set on both members: a freshly created (sync_id
     * 0) pair wouldn't exercise wait_member_synced()'s own sync_id check
     * below, and F11 exclusion is meant to apply on top of an otherwise
     * ordinary in-sync mirror, not only to never-opened copies. */
    RawstorObjectSyncState established{};
    established.epoch = 1;
    established.sync_id = 0xaaaaaaaaaaaaaaaaull;
    established.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    ASSERT_EQ(target_set_sync_state(queue, members.target(0), established), 0);
    ASSERT_EQ(target_set_sync_state(queue, members.target(1), established), 0);

    /* Distinct content on the full-size member only, so a successful
     * online resync back onto member1 is observable below. */
    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);

    /* member1's copy is short of the mirror's logical size -- e.g. a
     * block-device member whose extent/volblocksize rounding went the
     * other way, or a truncated/partial copy (docs/mirroring.md, F11:
     * "Physical < logical -> the copy is invalid (treat as F10)"). */
    fs::resize_file(members.dat(1), (1ull << 20) - 4096);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* The short member is excluded at open (not silently adopted as a
     * smaller logical size) and resynced online. */
    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.sync_state.sync_id, b.sync_state.sync_id);
    EXPECT_EQ(b.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(a.spec.size, spec.size);
    EXPECT_EQ(b.spec.size, spec.size);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(1), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

TEST(MirrorResyncTest, resync_under_concurrent_writes) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a7");

    const uint64_t size = 8ull << 20;
    RawstorObjectSpec spec{
        .size = size,
        .width = 2,
        .chunk_size = 0,
    };
    ASSERT_EQ(target_create(queue, members.target_all(), spec), 0);

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

    /* Pre-existing content on the fresh member across every chunk. */
    for (uint64_t off = 0; off < size; off += 1ull << 20) {
        std::string block(4096, 'S');
        object_write_single(
            queue, members.target(0), block.data(), block.size(), (off_t)off
        );
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);

    /* Client writes race the sweeper across the whole object. */
    for (int k = 0; k < 16; ++k) {
        std::string block(4096, (char)('A' + k));
        object_write(
            queue, object, block.data(), block.size(),
            (off_t)((uint64_t)k * (size / 16) + 512), 0
        );
    }

    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    /* Byte-for-byte identity after the rejoin. */
    EXPECT_EQ(read_file(members.dat(0)), read_file(members.dat(1)));

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(1), &b), 0);
    EXPECT_EQ(a.sync_state.sync_id, b.sync_state.sync_id);
    EXPECT_EQ(a.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
    EXPECT_EQ(b.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
}

TEST(MirrorResyncTest, probe_rejoins_recreated_arm) {
    Queue queue(16);
    Members members(3, "00000000-0000-7000-8000-0000000000a8");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 3,
        .chunk_size = 0,
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
        .width = 1,
        .chunk_size = 0,
    };
    ASSERT_EQ(target_create(queue, members.target(2), member_spec), 0);

    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(2))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta c{};
    ASSERT_EQ(target_meta(queue, members.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, members.target(2), &c), 0);
    EXPECT_EQ(a.sync_state.sync_id, c.sync_state.sync_id);
    EXPECT_EQ(c.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    RawstorObject* member = nullptr;
    ASSERT_EQ(target_open(queue, members.target(2), &member), 0);
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, member), 0);
}

TEST(MirrorQuorumTest, clean_close_stable_identity) {
    Queue queue(16);
    Members members(2, "00000000-0000-7000-8000-0000000000a6");

    RawstorObjectSpec spec{
        .size = 1ull << 20,
        .width = 2,
        .chunk_size = 0,
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
    EXPECT_NE(first.sync_state.sync_id, 0u);
    EXPECT_EQ(first.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);

    /* A healthy second session must not churn the identity. */
    ASSERT_EQ(target_open(queue, members.target_all(), &object), 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta second{};
    ASSERT_EQ(target_meta(queue, members.target(0), &second), 0);
    EXPECT_EQ(second.sync_state.sync_id, first.sync_state.sync_id);
    EXPECT_EQ(second.sync_state.epoch, first.sync_state.epoch);
    EXPECT_EQ(second.sync_state.state, RAWSTOR_OBJECT_SYNC_STATE_CLEAN);
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

    RawstorOSTFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .reserved1 = 0,
        .reserved2 = 0,
    };

    /*
     * The object is CLEAN, so the slot layer still retries reads
     * transparently: the member serves the error on the initial session and
     * on two reopened ones before the read fails over to the second member.
     * The repair then lands on the last reopened session.
     */
    // Target::open() fetches spec() from every reachable slot
    // concurrently (see its own comment) -- both server1's and server2's
    // own first session get their own SPEC ahead of their SET_OBJECT+
    // META. width on the wire here is whatever this mock server
    // happens to answer with -- Target::open() always overwrites it
    // with uris.size() regardless (see its own comment), so the value
    // scripted below isn't load-bearing. Both members still go through
    // Slot::open()'s own combined SET_OBJECT+META step (see its
    // own comment), concurrently, once every spec() has answered. Every
    // later low-level reconnect (invalidate_backend()) goes through
    // Backend::set_object() only, no SPEC of its own (invalidate_backend()
    // only set_object()s -- see its own comment) -- but it always folds
    // its own META fetch in on success, so each reopened session below
    // still gets its own SET_OBJECT+META pair.
    {
        rawstor::tests::Session s(server1);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_read_error(RAWSTOR_MAGIC, 3, -EIO);
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
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
        s.cmd_write(RAWSTOR_MAGIC, 4, 4);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_read(RAWSTOR_MAGIC, 3, "pong", 4);
        s.cmd_set_state(RAWSTOR_MAGIC, 4, 0);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string data(4, '\0');
    object_read(queue, object, data.data(), data.size(), 0);
    EXPECT_EQ(data, "pong");

    /* Drain the detached repair before tearing the object down. */
    for (int i = 0; i < 100; ++i) {
        rawio_wait_timeout(queue, 10);
    }

    EXPECT_EQ(object_close(queue, object), 0);
}

/*
 * Degrade & continue: a write fails on one member, the survivor durably
 * records the exclusion (SET_SYNC_STATE) and the write is acknowledged; the
 * next write goes to the survivor only.
 */
TEST(MirrorOstTest, degrade_and_continue) {
    Queue queue(16);
    rawstor::tests::Server server1(8753, 256);
    rawstor::tests::Server server2(8754, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-0000000000b1,"
        "ost://127.0.0.1:8754/00000000-0000-7000-8000-0000000000b1";

    RawstorOSTFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .reserved1 = 0,
        .reserved2 = 0,
    };

    // Target::open() fetches spec() from every reachable slot
    // concurrently (see its own comment) -- both server1's and server2's
    // own session get their own SPEC ahead of their SET_OBJECT+META.
    // width on the wire here is whatever this mock server happens to
    // answer with -- Target::open() always overwrites it with
    // uris.size() regardless (see its own comment), so the value
    // scripted below isn't load-bearing. Both members still go through
    // Slot::open()'s own combined SET_OBJECT+META step (see its
    // own comment), concurrently, once every spec() has answered.
    {
        rawstor::tests::Session s(server1);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 4, -EIO);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
        s.cmd_write(RAWSTOR_MAGIC, 4, 4);
        /* Degrade barrier: the exclusion is recorded on the survivor. */
        s.cmd_set_state(RAWSTOR_MAGIC, 5, 0);
        /* Subsequent writes go to the survivor only. */
        s.cmd_write(RAWSTOR_MAGIC, 6, 4);
        /*
         * object_close() below is a clean close (see Chunk::close()'s own
         * doc comment): flush, then a durable CLEAN mark on the sole
         * survivor.
         */
        s.cmd_flush(RAWSTOR_MAGIC, 7, 0);
        s.cmd_set_state(RAWSTOR_MAGIC, 8, 0);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);

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

    RawstorOSTFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .reserved1 = 0,
        .reserved2 = 0,
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        /* Both members reject the first write's dirty-barrier update. */
        s.cmd_set_state(RAWSTOR_MAGIC, 3, -EINVAL);
    }
    {
        rawstor::tests::Session s(server2);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, -EINVAL);
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

    RawstorOSTFrameMetaPayload legacy = {
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        .chunk_shift = 0,
        .width = 1,
        .reserved1 = 0,
        .reserved2 = 0,
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
        s.cmd_write(RAWSTOR_MAGIC, 4, 4);
        /* member0's session is "lost" (a transport-class error, not a
         * payload one) right while the object is DIRTY; transparent retry
         * is already off by this point, so _read() moves on to member1
         * after this one failure. */
        s.cmd_read_error(RAWSTOR_MAGIC, 5, -EIO);
    }
    {
        rawstor::tests::Session s(server2);
        s.cmd_spec(RAWSTOR_MAGIC, 0, 0, 1ull << 20, 2);
        s.cmd_set_object(RAWSTOR_MAGIC, 1, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 2, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
        s.cmd_write(RAWSTOR_MAGIC, 4, 4);
        s.cmd_read(RAWSTOR_MAGIC, 5, "ping", 4);
        /* The degrade barrier bumps epoch/sync_id on the survivor -- member0
         * is excluded durably even though it never lost this read. */
        s.cmd_set_state(RAWSTOR_MAGIC, 6, 0);
        /* Chunk::close(): flush + final CLEAN mark, now on the sole
         * survivor. */
        s.cmd_flush(RAWSTOR_MAGIC, 7, 0);
        s.cmd_set_state(RAWSTOR_MAGIC, 8, 0);
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
    EXPECT_EQ(object_close(queue, object), 0);
}

} // unnamed namespace
