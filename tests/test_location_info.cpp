#include "server.hpp"
#include "session.hpp"

#include "rawio_sync.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <memory>

namespace {

ssize_t location_info(
    rawio::Queue& queue, const std::string& location, RawstorLocationInfo* info
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_info(&queue, location.c_str(), info, cb, data);
    });
}

ssize_t target_create(
    rawio::Queue& queue, const std::string& target,
    const RawstorObjectSpec& spec
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_create(&queue, target.c_str(), &spec, cb, data);
    });
}

ssize_t target_remove(rawio::Queue& queue, const std::string& target) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_remove(&queue, target.c_str(), cb, data);
    });
}

TEST(FileLocationInfoTest, empty_then_used) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / "test_location_info";
    std::filesystem::create_directories(location_path);
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000005";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    ssize_t res = location_info(*queue, location, &info);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info.used, (uint64_t)0);
    EXPECT_GT(info.total, (uint64_t)0);

    RawstorObjectSpec spec{.size = 1ull << 20, .mirror_count = 0};
    res = target_create(*queue, target, spec);
    EXPECT_EQ(res, 0);

    res = location_info(*queue, location, &info);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info.used, (uint64_t)(1ull << 20));
    EXPECT_GT(info.total, (uint64_t)0);

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(FileLocationInfoTest, multi_location_aggregation) {
    std::filesystem::path location_a_path =
        std::filesystem::temp_directory_path() / "test_location_info_a";
    std::filesystem::path location_b_path =
        std::filesystem::temp_directory_path() / "test_location_info_b";
    std::filesystem::create_directories(location_a_path);
    std::filesystem::create_directories(location_b_path);

    rawstd::URI location_a_uri(
        (std::ostringstream() << "file://" << location_a_path.string()).str()
    );
    rawstd::URI location_b_uri(
        (std::ostringstream() << "file://" << location_b_path.string()).str()
    );
    std::string uuid_a = "00000000-0000-7000-8000-000000000006";
    std::string uuid_b = "00000000-0000-7000-8000-000000000007";
    std::string target_a = rawstd::URI(location_a_uri, uuid_a).str();
    std::string target_b = rawstd::URI(location_b_uri, uuid_b).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec_a{.size = 1ull << 20, .mirror_count = 0};
    ssize_t res = target_create(*queue, target_a, spec_a);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec spec_b{.size = 3ull << 20, .mirror_count = 0};
    res = target_create(*queue, target_b, spec_b);
    EXPECT_EQ(res, 0);

    std::string location = location_a_uri.str() + "," + location_b_uri.str();

    RawstorLocationInfo info = {};
    res = location_info(*queue, location, &info);
    EXPECT_EQ(res, 0);
    // used takes the max across backends, not the sum.
    EXPECT_EQ(info.used, (uint64_t)(3ull << 20));

    RawstorLocationInfo info_a = {};
    res = location_info(*queue, location_a_uri.str(), &info_a);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info_a.used, (uint64_t)(1ull << 20));

    RawstorLocationInfo info_b = {};
    res = location_info(*queue, location_b_uri.str(), &info_b);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info_b.used, (uint64_t)(3ull << 20));

    // total is capped by the smallest backend.
    EXPECT_EQ(info.total, std::min(info_a.total, info_b.total));

    res = target_remove(*queue, target_a);
    EXPECT_EQ(res, 0);
    res = target_remove(*queue, target_b);
    EXPECT_EQ(res, 0);
}

TEST(OstLocationInfoTest, location_info) {
    rawstor::tests::Server server(8754, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8754");
    std::string location = location_uri.str();

    RawstorLocationInfo sent_info{
        .used = 1ull << 20,
        .total = 1ull << 30,
    };

    {
        rawstor::tests::Session s(server);
        s.cmd_location_info(RAWSTOR_MAGIC, 0, sent_info);
    }

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorLocationInfo info = {};
    ssize_t res = location_info(*queue, location, &info);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info.used, sent_info.used);
    EXPECT_EQ(info.total, sent_info.total);
}

} // unnamed namespace
