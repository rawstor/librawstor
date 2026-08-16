#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>

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

int callback(RawstorObject*, size_t, size_t result, int error, void* data) {
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

    fs::path dat(size_t i) const { return _dirs[i] / (_uuid + ".dat"); }
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
        object, buf, size, offset, /*sync=*/false, callback, cb.get()
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

int close_cb(int result, void* data) {
    *static_cast<int*>(data) = result ? result : 1;
    return 0;
}

void object_close_clean(Queue& queue, RawstorObject* object) {
    int done = 0;
    int res = rawstor_object_close_async(object, close_cb, &done);
    ASSERT_EQ(res, 0);
    while (!done) {
        queue.wait();
    }
    EXPECT_EQ(done, 1);
}

void object_write_single(
    Queue& queue, const std::string& target, const void* buf, size_t size,
    off_t offset
) {
    RawstorObject* member = nullptr;
    ASSERT_EQ(rawstor_object_open(queue, target.c_str(), &member), 0);
    object_write(queue, member, buf, size, offset, 0);
    EXPECT_EQ(rawstor_object_close(member), 0);
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
        if (rawstor_object_meta(fresh.c_str(), &a) != 0) {
            continue;
        }
        if (rawstor_object_meta(behind.c_str(), &b) != 0) {
            continue;
        }
        if (b.state != RAWSTOR_OBJECT_STATE_SYNCING && a.sync_id != 0 &&
            b.sync_id == a.sync_id) {
            return true;
        }
    }
    return false;
}

TEST(MirrorQuorumTest, open_refused_without_quorum_n2) {
    Members members(2, "00000000-0000-7000-8000-0000000000a0");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    members.drop(1);

    Queue queue(16);
    RawstorObject* object = nullptr;
    int res = rawstor_object_open(queue, members.target_all().c_str(), &object);
    EXPECT_EQ(res, -ENOTCONN);
    EXPECT_EQ(object, nullptr);
}

TEST(MirrorQuorumTest, degraded_open_with_quorum_n3) {
    Members members(3, "00000000-0000-7000-8000-0000000000a1");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    members.drop(2);

    Queue queue(16);
    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    /* The survivors got a fresh sync set; both are CLEAN and identical. */
    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &a), 0);
    ASSERT_EQ(rawstor_object_meta(members.target(1).c_str(), &b), 0);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_NE(a.sync_id, 0u);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(a.epoch, 1u);
    EXPECT_EQ(b.epoch, 1u);

    /* Both survivors carry the data. */
    for (size_t i = 0; i < 2; ++i) {
        RawstorObject* member = nullptr;
        ASSERT_EQ(
            rawstor_object_open(queue, members.target(i).c_str(), &member), 0
        );
        std::string data(4, '\0');
        object_read(queue, member, data.data(), data.size(), 0);
        EXPECT_EQ(data, "ping");
        EXPECT_EQ(rawstor_object_close(member), 0);
    }
}

TEST(MirrorQuorumTest, stale_arm_resynced) {
    Members members(2, "00000000-0000-7000-8000-0000000000a2");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    /* Arm 0 is one sync set ahead of member 1. */
    RawstorObjectMeta fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    fresh.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(rawstor_object_set_state(members.target(0).c_str(), &fresh), 0);

    RawstorObjectMeta stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    stale.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(rawstor_object_set_state(members.target(1).c_str(), &stale), 0);

    Queue queue(16);

    /* Distinct content on the fresh member only. */
    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );

    /* The stale member is resynced online while the object is open. */
    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &a), 0);
    ASSERT_EQ(rawstor_object_meta(members.target(1).c_str(), &b), 0);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);

    /* The rejoined member carries the fresh member's data now. */
    RawstorObject* member = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target(1).c_str(), &member), 0
    );
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(rawstor_object_close(member), 0);
}

TEST(MirrorQuorumTest, split_brain_refused) {
    Members members(2, "00000000-0000-7000-8000-0000000000a3");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    /* Disjoint histories sharing only a common ancestor. */
    RawstorObjectMeta a{};
    a.epoch = 2;
    a.sync_id = 0x1111111111111111ull;
    a.sync_id_history[0] = 0x3333333333333333ull;
    a.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(rawstor_object_set_state(members.target(0).c_str(), &a), 0);

    RawstorObjectMeta b{};
    b.epoch = 2;
    b.sync_id = 0x2222222222222222ull;
    b.sync_id_history[0] = 0x3333333333333333ull;
    b.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(rawstor_object_set_state(members.target(1).c_str(), &b), 0);

    Queue queue(16);
    RawstorObject* object = nullptr;
    int res = rawstor_object_open(queue, members.target_all().c_str(), &object);
    EXPECT_EQ(res, -ENOTRECOVERABLE);
    EXPECT_EQ(object, nullptr);
}

TEST(MirrorQuorumTest, all_dirty_same_sync_id_opens) {
    Members members(2, "00000000-0000-7000-8000-0000000000a4");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    /* Unclean shutdown: every copy DIRTY within the same sync set. */
    RawstorObjectMeta dirty{};
    dirty.epoch = 1;
    dirty.sync_id = 0x4444444444444444ull;
    dirty.state = RAWSTOR_OBJECT_STATE_DIRTY;
    ASSERT_EQ(
        rawstor_object_set_state(members.target_all().c_str(), &dirty), 0
    );

    Queue queue(16);
    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    /* Full membership, established sync set: no identity churn. */
    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &a), 0);
    ASSERT_EQ(rawstor_object_meta(members.target(1).c_str(), &b), 0);
    EXPECT_EQ(a.sync_id, dirty.sync_id);
    EXPECT_EQ(b.sync_id, dirty.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);
}

TEST(MirrorQuorumTest, syncing_arm_resynced) {
    Members members(2, "00000000-0000-7000-8000-0000000000a5");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    RawstorObjectMeta established{};
    established.epoch = 1;
    established.sync_id = 0x5555555555555555ull;
    established.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(
        rawstor_object_set_state(members.target_all().c_str(), &established), 0
    );

    /* An interrupted resync left the member marked SYNCING: untrusted. */
    RawstorObjectMeta syncing = established;
    syncing.state = RAWSTOR_OBJECT_STATE_SYNCING;
    ASSERT_EQ(rawstor_object_set_state(members.target(1).c_str(), &syncing), 0);

    Queue queue(16);

    std::string ping = "ping";
    object_write_single(queue, members.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );

    /* The untrusted member is resynced from scratch. */
    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(1))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &a), 0);
    ASSERT_EQ(rawstor_object_meta(members.target(1).c_str(), &b), 0);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);

    RawstorObject* member = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target(1).c_str(), &member), 0
    );
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(rawstor_object_close(member), 0);
}

TEST(MirrorResyncTest, resync_under_concurrent_writes) {
    Members members(2, "00000000-0000-7000-8000-0000000000a7");

    const uint64_t size = 8ull << 20;
    RawstorObjectSpec spec{};
    spec.size = size;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    RawstorObjectMeta fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    fresh.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(rawstor_object_set_state(members.target(0).c_str(), &fresh), 0);

    RawstorObjectMeta stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    stale.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(rawstor_object_set_state(members.target(1).c_str(), &stale), 0);

    Queue queue(16);

    /* Pre-existing content on the fresh member across every chunk. */
    for (uint64_t off = 0; off < size; off += 1ull << 20) {
        std::string block(4096, 'S');
        object_write_single(
            queue, members.target(0), block.data(), block.size(), (off_t)off
        );
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );

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
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &a), 0);
    ASSERT_EQ(rawstor_object_meta(members.target(1).c_str(), &b), 0);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);
}

TEST(MirrorResyncTest, probe_rejoins_recreated_arm) {
    Members members(3, "00000000-0000-7000-8000-0000000000a8");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    /* The third member is lost entirely (disk gone). */
    members.drop(2);

    Queue queue(16);
    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);

    /* The member is reprovisioned empty; the probe picks it up and resyncs. */
    ASSERT_EQ(rawstor_object_create(members.target(2).c_str(), &spec), 0);

    EXPECT_TRUE(
        wait_member_synced(queue, members.target(0), members.target(2))
    );

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta c{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &a), 0);
    ASSERT_EQ(rawstor_object_meta(members.target(2).c_str(), &c), 0);
    EXPECT_EQ(a.sync_id, c.sync_id);
    EXPECT_EQ(c.state, RAWSTOR_OBJECT_STATE_CLEAN);

    RawstorObject* member = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target(2).c_str(), &member), 0
    );
    std::string data(4, '\0');
    object_read(queue, member, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(rawstor_object_close(member), 0);
}

TEST(MirrorQuorumTest, clean_close_stable_identity) {
    Members members(2, "00000000-0000-7000-8000-0000000000a6");

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    ASSERT_EQ(rawstor_object_create(members.target_all().c_str(), &spec), 0);

    Queue queue(16);

    /* First session establishes the sync set. */
    RawstorObject* object = nullptr;
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );
    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta first{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &first), 0);
    EXPECT_NE(first.sync_id, 0u);
    EXPECT_EQ(first.state, RAWSTOR_OBJECT_STATE_CLEAN);

    /* A healthy second session must not churn the identity. */
    ASSERT_EQ(
        rawstor_object_open(queue, members.target_all().c_str(), &object), 0
    );
    object_write(queue, object, ping.data(), ping.size(), 8, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta second{};
    ASSERT_EQ(rawstor_object_meta(members.target(0).c_str(), &second), 0);
    EXPECT_EQ(second.sync_id, first.sync_id);
    EXPECT_EQ(second.epoch, first.epoch);
    EXPECT_EQ(second.state, RAWSTOR_OBJECT_STATE_CLEAN);
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

    RawstorOSTFrameMetaBody legacy = {
        .obj_id = {},
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_STATE_CLEAN,
        .member_kind = 0,
        .width = 0,
        .reserved = 0,
        .volume_id = {},
        .logical_index = 0,
        .chunk_size = 0,
        .snap_version = 0,
    };

    /*
     * The object is CLEAN, so the connection layer still retries reads
     * transparently: the member serves the error on the initial session and
     * on two reopened ones before the read fails over to the second member.
     * The repair then lands on the last reopened session.
     */
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read_error(RAWSTOR_MAGIC, 2, -EIO);
    }
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_read_error(RAWSTOR_MAGIC, 1, -EIO);
    }
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_read_error(RAWSTOR_MAGIC, 1, -EIO);
        s.cmd_set_state(RAWSTOR_MAGIC, 2, 0);
        s.cmd_write(RAWSTOR_MAGIC, 3, 4);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read(RAWSTOR_MAGIC, 2, "pong", 4);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(rawstor_object_open(queue, target.c_str(), &object), 0);

    std::string data(4, '\0');
    object_read(queue, object, data.data(), data.size(), 0);
    EXPECT_EQ(data, "pong");

    /* Drain the detached repair before tearing the object down. */
    for (int i = 0; i < 100; ++i) {
        rawio_wait_timeout(queue, 10);
    }

    EXPECT_EQ(rawstor_object_close(object), 0);
}

/*
 * Degrade & continue: a write fails on one member, the survivor durably
 * records the exclusion (SET_STATE) and the write is acknowledged; the
 * next write goes to the survivor only.
 */
TEST(MirrorOstTest, degrade_and_continue) {
    Queue queue(16);
    rawstor::tests::Server server1(8753, 256);
    rawstor::tests::Server server2(8754, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-0000000000b1,"
        "ost://127.0.0.1:8754/00000000-0000-7000-8000-0000000000b1";

    RawstorOSTFrameMetaBody legacy = {
        .obj_id = {},
        .size = 1ull << 20,
        .epoch = 0,
        .sync_id = 0,
        .sync_id_history = {},
        .state = RAWSTOR_OBJECT_STATE_CLEAN,
        .member_kind = 0,
        .width = 0,
        .reserved = 0,
        .volume_id = {},
        .logical_index = 0,
        .chunk_size = 0,
        .snap_version = 0,
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 2, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 3, -EIO);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_meta(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 2, 0);
        s.cmd_write(RAWSTOR_MAGIC, 3, 4);
        /* Degrade barrier: the exclusion is recorded on the survivor. */
        s.cmd_set_state(RAWSTOR_MAGIC, 4, 0);
        /* Subsequent writes go to the survivor only. */
        s.cmd_write(RAWSTOR_MAGIC, 5, 4);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(rawstor_object_open(queue, target.c_str(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);

    EXPECT_EQ(rawstor_object_close(object), 0);
}

} // unnamed namespace
