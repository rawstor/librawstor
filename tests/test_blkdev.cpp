#include "blkdev_meta.hpp"
#include "blkdev_session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <functional>
#include <string>
#include <vector>

#include <cerrno>

namespace {

/*
 * Exposes the protected run_async()/run_async_capture() command machinery
 * without requiring an actual LVM/ZFS setup.
 */
class CmdSession final : public rawstor::BlkdevSession {
protected:
    std::string device_path(const RawstdUUID&) const override { return ""; }

    void _meta_identity(
        const RawstdUUID&, std::function<void(const RawstorObjectMeta&, int)>&&
    ) override {}

public:
    CmdSession(rawio::Queue& queue, const rawstd::URI& location) :
        BlkdevSession(Private(), queue, location) {}

    void create(
        const RawstdUUID&, const RawstorObjectSpec&, std::function<void(int)>&&
    ) override {}

    void remove(const RawstdUUID&, std::function<void(int)>&&) override {}

    void set_state(
        const RawstdUUID&, const RawstorObjectMeta&, std::function<void(int)>&&
    ) override {}

    void
    run(std::vector<std::string> cmd, std::string wait_path,
        std::function<void(int)>&& cb) {
        run_async(std::move(cmd), std::move(wait_path), std::move(cb));
    }

    void capture(
        std::vector<std::string> cmd, std::function<void(std::string, int)>&& cb
    ) {
        run_async_capture(std::move(cmd), std::move(cb));
    }
};

class BlkdevCmdTest : public ::testing::Test {
protected:
    std::unique_ptr<rawio::Queue> _queue;
    std::unique_ptr<CmdSession> _session;

    void SetUp() override {
        _queue = rawio::Queue::create(64);
        rawstd::URI location(std::string("lvm:///dev/test_vg"));
        _session = std::make_unique<CmdSession>(*_queue, location);
    }

    int run(std::vector<std::string> cmd, std::string wait_path) {
        bool done = false;
        int result = -1;

        _session->run(
            std::move(cmd), std::move(wait_path), [&done, &result](int error) {
                result = error;
                done = true;
            }
        );

        while (!done) {
            _queue->wait_timeout(1000);
        }

        return result;
    }

    std::pair<std::string, int> capture(std::vector<std::string> cmd) {
        bool done = false;
        std::string output;
        int result = -1;

        _session->capture(
            std::move(cmd),
            [&done, &output, &result](std::string out, int error) {
                output = std::move(out);
                result = error;
                done = true;
            }
        );

        while (!done) {
            _queue->wait_timeout(1000);
        }

        return {output, result};
    }
};

std::string find_block_device() {
    std::error_code ec;
    for (const auto& entry :
         std::filesystem::directory_iterator("/sys/block", ec)) {
        std::filesystem::path dev = "/dev" / entry.path().filename();
        if (std::filesystem::exists(dev, ec)) {
            return dev.string();
        }
    }
    return "";
}

TEST_F(BlkdevCmdTest, success) {
    EXPECT_EQ(run({"true"}, ""), 0);
}

TEST_F(BlkdevCmdTest, nonzero_exit) {
    EXPECT_EQ(run({"false"}, ""), EIO);
}

TEST_F(BlkdevCmdTest, missing_binary) {
    EXPECT_EQ(run({"/no/such/binary"}, ""), ENOENT);
}

TEST_F(BlkdevCmdTest, slow_child) {
    EXPECT_EQ(run({"sleep", "0.3"}, ""), 0);
}

TEST_F(BlkdevCmdTest, wait_existing_device) {
    std::string dev = find_block_device();
    if (dev.empty()) {
        GTEST_SKIP() << "no block devices available";
    }

    EXPECT_EQ(run({"true"}, dev), 0);
}

TEST_F(BlkdevCmdTest, wait_missing_device_times_out) {
    auto start = std::chrono::steady_clock::now();

    EXPECT_EQ(run({"true"}, "/dev/no_such_rawstor_device"), ETIMEDOUT);

    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - start
    )
                       .count();
    EXPECT_GE(elapsed, 4500);
    EXPECT_LT(elapsed, 10000);
}

TEST_F(BlkdevCmdTest, capture_reads_stdout) {
    auto [output, error] = capture({"echo", "-n", "hello"});
    EXPECT_EQ(error, 0);
    EXPECT_EQ(output, "hello");
}

TEST_F(BlkdevCmdTest, capture_reads_multiline_stdout) {
    /* Exercises the read loop looping past a single 4096-byte chunk. */
    std::string big(10000, 'x');
    auto [output, error] = capture({"printf", "%s", big});
    EXPECT_EQ(error, 0);
    EXPECT_EQ(output, big);
}

TEST_F(BlkdevCmdTest, capture_empty_stdout) {
    auto [output, error] = capture({"true"});
    EXPECT_EQ(error, 0);
    EXPECT_EQ(output, "");
}

TEST_F(BlkdevCmdTest, capture_nonzero_exit) {
    auto [output, error] = capture({"false"});
    EXPECT_EQ(error, EIO);
}

TEST_F(BlkdevCmdTest, capture_missing_binary) {
    auto [output, error] = capture({"/no/such/binary"});
    EXPECT_EQ(error, ENOENT);
}

TEST(BlkdevMetaTest, encode_decode_round_trip) {
    RawstorObjectMeta meta{};
    meta.size = 12345; /* ignored by encode/decode: identity fields only */
    meta.state = RAWSTOR_OBJECT_STATE_DIRTY;
    meta.epoch = 7;
    meta.sync_id = 0x1122334455667788ull;
    meta.sync_id_history[0] = 0xaabbccddeeff0011ull;
    meta.sync_id_history[1] = 1;
    meta.sync_id_history[2] = 2;
    meta.sync_id_history[3] = 3;

    std::string encoded = rawstor::blkdev_meta_encode(meta);

    RawstorObjectMeta decoded{};
    ASSERT_TRUE(rawstor::blkdev_meta_decode(encoded, &decoded));
    EXPECT_EQ(decoded.state, meta.state);
    EXPECT_EQ(decoded.epoch, meta.epoch);
    EXPECT_EQ(decoded.sync_id, meta.sync_id);
    EXPECT_EQ(decoded.sync_id_history[0], meta.sync_id_history[0]);
    EXPECT_EQ(decoded.sync_id_history[1], meta.sync_id_history[1]);
    EXPECT_EQ(decoded.sync_id_history[2], meta.sync_id_history[2]);
    EXPECT_EQ(decoded.sync_id_history[3], meta.sync_id_history[3]);
}

TEST(BlkdevMetaTest, decode_rejects_empty_string) {
    /* A missing property/tag must never be mistaken for a valid record. */
    RawstorObjectMeta decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("", &decoded));
}

TEST(BlkdevMetaTest, decode_rejects_zfs_unset_marker) {
    RawstorObjectMeta decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("-", &decoded));
}

TEST(BlkdevMetaTest, decode_rejects_malformed_string) {
    RawstorObjectMeta decoded{};
    EXPECT_FALSE(rawstor::blkdev_meta_decode("not the right format", &decoded));
}

TEST(BlkdevMetaTest, find_tag_among_multiple) {
    std::string tags = "  rawstor.meta=state=0:epoch=0,unrelated_tag  \n";
    EXPECT_EQ(
        rawstor::blkdev_find_tag(tags, "rawstor.meta="), "state=0:epoch=0"
    );
}

TEST(BlkdevMetaTest, find_tag_not_present) {
    std::string tags = "unrelated_tag,other.thing=1";
    EXPECT_EQ(rawstor::blkdev_find_tag(tags, "rawstor.meta="), "");
}

TEST(BlkdevMetaTest, find_tag_empty_list) {
    EXPECT_EQ(rawstor::blkdev_find_tag("   \n", "rawstor.meta="), "");
}

} // unnamed namespace
