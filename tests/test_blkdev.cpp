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
 * Exposes the protected run_async() command machinery without requiring an
 * actual LVM/ZFS setup.
 */
class CmdSession final : public rawstor::BlkdevSession {
protected:
    std::string device_path(const RawstdUUID&) const override { return ""; }

public:
    CmdSession(rawio::Queue& queue, const rawstd::URI& location) :
        BlkdevSession(queue, location) {}

    void create(
        const RawstdUUID&, const RawstorObjectSpec&, std::function<void(int)>&&
    ) override {}

    void remove(const RawstdUUID&, std::function<void(int)>&&) override {}

    void
    run(std::vector<std::string> cmd, std::string wait_path,
        std::function<void(int)>&& cb) {
        run_async(std::move(cmd), std::move(wait_path), std::move(cb));
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

} // unnamed namespace
