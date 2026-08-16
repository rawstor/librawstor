#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <filesystem>

namespace {

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

    RawstorLocationInfo info = {};
    int res = rawstor_location_info(location.c_str(), &info);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info.used, (uint64_t)0);
    EXPECT_GT(info.total, (uint64_t)0);

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    res = rawstor_object_create(target.c_str(), &spec);
    EXPECT_EQ(res, 0);

    res = rawstor_location_info(location.c_str(), &info);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info.used, (uint64_t)(1ull << 20));
    EXPECT_GT(info.total, (uint64_t)0);

    res = rawstor_object_remove(target.c_str());
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

    RawstorObjectSpec spec_a{};
    spec_a.size = 1ull << 20;
    int res = rawstor_object_create(target_a.c_str(), &spec_a);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec spec_b{};
    spec_b.size = 3ull << 20;
    res = rawstor_object_create(target_b.c_str(), &spec_b);
    EXPECT_EQ(res, 0);

    std::string location = location_a_uri.str() + "," + location_b_uri.str();

    RawstorLocationInfo info = {};
    res = rawstor_location_info(location.c_str(), &info);
    EXPECT_EQ(res, 0);
    // used takes the max across backends, not the sum.
    EXPECT_EQ(info.used, (uint64_t)(3ull << 20));

    RawstorLocationInfo info_a = {};
    res = rawstor_location_info(location_a_uri.str().c_str(), &info_a);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info_a.used, (uint64_t)(1ull << 20));

    RawstorLocationInfo info_b = {};
    res = rawstor_location_info(location_b_uri.str().c_str(), &info_b);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info_b.used, (uint64_t)(3ull << 20));

    // total is capped by the smallest backend.
    EXPECT_EQ(info.total, std::min(info_a.total, info_b.total));

    res = rawstor_object_remove(target_a.c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target_b.c_str());
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

    RawstorLocationInfo info = {};
    int res = rawstor_location_info(location.c_str(), &info);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(info.used, sent_info.used);
    EXPECT_EQ(info.total, sent_info.total);
}

} // unnamed namespace
