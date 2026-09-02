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

// Every control-plane operation (create/open/meta/set_state/close) is
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

ssize_t
target_meta(Queue& queue, const std::string& target, RawstorObjectMeta* meta) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_meta(queue, target.c_str(), meta, cb, data);
    });
}

ssize_t target_set_state(
    Queue& queue, const std::string& target, const RawstorObjectMeta& meta
) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_target_set_state(queue, target.c_str(), &meta, cb, data);
    });
}

ssize_t object_close(Queue& queue, RawstorObject* object) {
    return rawstor::tests::sync_run(queue, [&](auto cb, void* data) {
        return rawstor_object_close(object, cb, data);
    });
}

/*
 * File-backed mirror arms in per-arm temp directories, sharing one UUID.
 */
class Arms {
private:
    std::vector<fs::path> _dirs;
    std::string _uuid;

public:
    Arms(size_t n, const std::string& uuid) : _uuid(uuid) {
        for (size_t i = 0; i < n; ++i) {
            std::ostringstream oss;
            oss << "test_mirror_arm" << i;
            fs::path dir = fs::temp_directory_path() / oss.str();
            fs::remove_all(dir);
            _dirs.push_back(dir);
        }
    }

    ~Arms() {
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

    // file::Backend keeps one data file per object, named after the UUID
    // alone (see get_target_path() in src/file_backend.cpp) -- no .dat/.spec
    // split.
    fs::path dat(size_t i) const { return _dirs[i] / _uuid; }
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
    int res =
        rawstor_object_pwrite(object, buf, size, offset, false, callback, cb.get());
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
// Object::close()'s own doc comment; there's no separate "_async"
// variant to reach for anymore.
void object_close_clean(Queue& queue, RawstorObject* object) {
    ssize_t res = object_close(queue, object);
    EXPECT_EQ(res, 0);
}

// A single-arm write, opened and closed via the same queue-driven
// rawstor_target_*() path as every other control-plane call here -- unlike
// the original commit, there's no synchronous rawstor_object_open() left to
// reach for.
void object_write_single(
    Queue& queue, const std::string& target, const void* buf, size_t size,
    off_t offset
) {
    RawstorObject* arm = nullptr;
    ASSERT_EQ(target_open(queue, target, &arm), 0);
    object_write(queue, arm, buf, size, offset, 0);
    EXPECT_EQ(object_close(queue, arm), 0);
}

/*
 * Drives the queue until the arm at `behind` reports the same established
 * sync set as the arm at `fresh` (and is not mid-resync anymore).
 */
bool wait_arm_synced(
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
        if (b.state != RAWSTOR_OBJECT_STATE_SYNCING && a.sync_id != 0 &&
            b.sync_id == a.sync_id) {
            return true;
        }
    }
    return false;
}

TEST(MirrorQuorumTest, open_refused_without_quorum_n2) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a0");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    arms.drop(1);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, arms.target_all(), &object);
    EXPECT_EQ(res, -ENOTCONN);
    EXPECT_EQ(object, nullptr);
}

TEST(MirrorQuorumTest, degraded_open_with_quorum_n3) {
    Queue queue(16);
    Arms arms(3, "00000000-0000-7000-8000-0000000000a1");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    arms.drop(2);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    /* The survivors got a fresh sync set; both are CLEAN and identical. */
    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, arms.target(1), &b), 0);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_NE(a.sync_id, 0u);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(a.epoch, 1u);
    EXPECT_EQ(b.epoch, 1u);

    /* Both survivors carry the data. */
    for (size_t i = 0; i < 2; ++i) {
        RawstorObject* arm = nullptr;
        ASSERT_EQ(target_open(queue, arms.target(i), &arm), 0);
        std::string data(4, '\0');
        object_read(queue, arm, data.data(), data.size(), 0);
        EXPECT_EQ(data, "ping");
        EXPECT_EQ(object_close(queue, arm), 0);
    }
}

TEST(MirrorQuorumTest, stale_arm_resynced) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a2");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    /* Arm 0 is one sync set ahead of arm 1. */
    RawstorObjectMeta fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    fresh.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(0), fresh), 0);

    RawstorObjectMeta stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    stale.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(1), stale), 0);

    /* Distinct content on the fresh arm only. */
    std::string ping = "ping";
    object_write_single(queue, arms.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);

    /* The stale arm is resynced online while the object is open. */
    EXPECT_TRUE(wait_arm_synced(queue, arms.target(0), arms.target(1)));

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, arms.target(1), &b), 0);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);

    /* The rejoined arm carries the fresh arm's data now. */
    RawstorObject* arm = nullptr;
    ASSERT_EQ(target_open(queue, arms.target(1), &arm), 0);
    std::string data(4, '\0');
    object_read(queue, arm, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, arm), 0);
}

TEST(MirrorQuorumTest, split_brain_refused) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a3");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    /* Disjoint histories sharing only a common ancestor. */
    RawstorObjectMeta a{};
    a.epoch = 2;
    a.sync_id = 0x1111111111111111ull;
    a.sync_id_history[0] = 0x3333333333333333ull;
    a.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(0), a), 0);

    RawstorObjectMeta b{};
    b.epoch = 2;
    b.sync_id = 0x2222222222222222ull;
    b.sync_id_history[0] = 0x3333333333333333ull;
    b.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(1), b), 0);

    RawstorObject* object = nullptr;
    ssize_t res = target_open(queue, arms.target_all(), &object);
    EXPECT_EQ(res, -ENOTRECOVERABLE);
    EXPECT_EQ(object, nullptr);
}

TEST(MirrorQuorumTest, all_dirty_same_sync_id_opens) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a4");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    /* Unclean shutdown: every copy DIRTY within the same sync set. */
    RawstorObjectMeta dirty{};
    dirty.epoch = 1;
    dirty.sync_id = 0x4444444444444444ull;
    dirty.state = RAWSTOR_OBJECT_STATE_DIRTY;
    ASSERT_EQ(target_set_state(queue, arms.target(0), dirty), 0);
    ASSERT_EQ(target_set_state(queue, arms.target(1), dirty), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    /* Full membership, established sync set: no identity churn. */
    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, arms.target(1), &b), 0);
    EXPECT_EQ(a.sync_id, dirty.sync_id);
    EXPECT_EQ(b.sync_id, dirty.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);
}

TEST(MirrorQuorumTest, syncing_arm_resynced) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a5");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    RawstorObjectMeta established{};
    established.epoch = 1;
    established.sync_id = 0x5555555555555555ull;
    established.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(0), established), 0);
    ASSERT_EQ(target_set_state(queue, arms.target(1), established), 0);

    /* An interrupted resync left the arm marked SYNCING: untrusted. */
    RawstorObjectMeta syncing = established;
    syncing.state = RAWSTOR_OBJECT_STATE_SYNCING;
    ASSERT_EQ(target_set_state(queue, arms.target(1), syncing), 0);

    std::string ping = "ping";
    object_write_single(queue, arms.target(0), ping.data(), ping.size(), 0);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);

    /* The untrusted arm is resynced from scratch. */
    EXPECT_TRUE(wait_arm_synced(queue, arms.target(0), arms.target(1)));

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, arms.target(1), &b), 0);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);

    RawstorObject* arm = nullptr;
    ASSERT_EQ(target_open(queue, arms.target(1), &arm), 0);
    std::string data(4, '\0');
    object_read(queue, arm, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, arm), 0);
}

TEST(MirrorResyncTest, resync_under_concurrent_writes) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a7");

    const uint64_t size = 8ull << 20;
    RawstorObjectSpec spec{.size = size};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    RawstorObjectMeta fresh{};
    fresh.epoch = 2;
    fresh.sync_id = 0x1111111111111111ull;
    fresh.sync_id_history[0] = 0x2222222222222222ull;
    fresh.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(0), fresh), 0);

    RawstorObjectMeta stale{};
    stale.epoch = 1;
    stale.sync_id = 0x2222222222222222ull;
    stale.state = RAWSTOR_OBJECT_STATE_CLEAN;
    ASSERT_EQ(target_set_state(queue, arms.target(1), stale), 0);

    /* Pre-existing content on the fresh arm across every chunk. */
    for (uint64_t off = 0; off < size; off += 1ull << 20) {
        std::string block(4096, 'S');
        object_write_single(
            queue, arms.target(0), block.data(), block.size(), (off_t)off
        );
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);

    /* Client writes race the sweeper across the whole object. */
    for (int k = 0; k < 16; ++k) {
        std::string block(4096, (char)('A' + k));
        object_write(
            queue, object, block.data(), block.size(),
            (off_t)((uint64_t)k * (size / 16) + 512), 0
        );
    }

    EXPECT_TRUE(wait_arm_synced(queue, arms.target(0), arms.target(1)));

    object_close_clean(queue, object);

    /* Byte-for-byte identity after the rejoin. */
    EXPECT_EQ(read_file(arms.dat(0)), read_file(arms.dat(1)));

    RawstorObjectMeta a{};
    RawstorObjectMeta b{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, arms.target(1), &b), 0);
    EXPECT_EQ(a.sync_id, b.sync_id);
    EXPECT_EQ(a.state, RAWSTOR_OBJECT_STATE_CLEAN);
    EXPECT_EQ(b.state, RAWSTOR_OBJECT_STATE_CLEAN);
}

TEST(MirrorResyncTest, probe_rejoins_recreated_arm) {
    Queue queue(16);
    Arms arms(3, "00000000-0000-7000-8000-0000000000a8");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    /* The third arm is lost entirely (disk gone). */
    arms.drop(2);

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);

    /* The arm is reprovisioned empty; the probe picks it up and resyncs. */
    ASSERT_EQ(target_create(queue, arms.target(2), spec), 0);

    EXPECT_TRUE(wait_arm_synced(queue, arms.target(0), arms.target(2)));

    object_close_clean(queue, object);

    RawstorObjectMeta a{};
    RawstorObjectMeta c{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &a), 0);
    ASSERT_EQ(target_meta(queue, arms.target(2), &c), 0);
    EXPECT_EQ(a.sync_id, c.sync_id);
    EXPECT_EQ(c.state, RAWSTOR_OBJECT_STATE_CLEAN);

    RawstorObject* arm = nullptr;
    ASSERT_EQ(target_open(queue, arms.target(2), &arm), 0);
    std::string data(4, '\0');
    object_read(queue, arm, data.data(), data.size(), 0);
    EXPECT_EQ(data, "ping");
    EXPECT_EQ(object_close(queue, arm), 0);
}

TEST(MirrorQuorumTest, clean_close_stable_identity) {
    Queue queue(16);
    Arms arms(2, "00000000-0000-7000-8000-0000000000a6");

    RawstorObjectSpec spec{.size = 1ull << 20};
    ASSERT_EQ(target_create(queue, arms.target_all(), spec), 0);

    /* First session establishes the sync set. */
    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);
    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta first{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &first), 0);
    EXPECT_NE(first.sync_id, 0u);
    EXPECT_EQ(first.state, RAWSTOR_OBJECT_STATE_CLEAN);

    /* A healthy second session must not churn the identity. */
    ASSERT_EQ(target_open(queue, arms.target_all(), &object), 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);
    object_close_clean(queue, object);

    RawstorObjectMeta second{};
    ASSERT_EQ(target_meta(queue, arms.target(0), &second), 0);
    EXPECT_EQ(second.sync_id, first.sync_id);
    EXPECT_EQ(second.epoch, first.epoch);
    EXPECT_EQ(second.state, RAWSTOR_OBJECT_STATE_CLEAN);
}

/*
 * OST mirror over two scripted servers: the first arm fails the read with
 * a payload error, the second serves the data; the client then repairs the
 * region on the first arm (dirty gate on both arms + rewrite).
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
    };

    /*
     * The object is CLEAN, so the connection layer still retries reads
     * transparently: the arm serves the error on the initial session and
     * on two reopened ones before the read fails over to the second arm.
     * The repair then lands on the last reopened session.
     */
    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_spec(RAWSTOR_MAGIC, 1, 0, legacy);
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
        s.cmd_spec(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_read(RAWSTOR_MAGIC, 2, "pong", 4);
        s.cmd_set_state(RAWSTOR_MAGIC, 3, 0);
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
 * Degrade & continue: a write fails on one arm, the survivor durably
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
    };

    {
        rawstor::tests::Session s(server1);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_spec(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 2, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 3, -EIO);
    }

    {
        rawstor::tests::Session s(server2);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_spec(RAWSTOR_MAGIC, 1, 0, legacy);
        s.cmd_set_state(RAWSTOR_MAGIC, 2, 0);
        s.cmd_write(RAWSTOR_MAGIC, 3, 4);
        /* Degrade barrier: the exclusion is recorded on the survivor. */
        s.cmd_set_state(RAWSTOR_MAGIC, 4, 0);
        /* Subsequent writes go to the survivor only. */
        s.cmd_write(RAWSTOR_MAGIC, 5, 4);
        /*
         * object_close() below is a clean close (see Object::close()'s own
         * doc comment): flush, then a durable CLEAN mark on the sole
         * survivor.
         */
        s.cmd_flush(RAWSTOR_MAGIC, 6, 0);
        s.cmd_set_state(RAWSTOR_MAGIC, 7, 0);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(target_open(queue, target, &object), 0);

    std::string ping = "ping";
    object_write(queue, object, ping.data(), ping.size(), 0, 0);
    object_write(queue, object, ping.data(), ping.size(), 8, 0);

    EXPECT_EQ(object_close(queue, object), 0);
}

} // unnamed namespace
