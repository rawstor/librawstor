#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>

namespace {

TEST(FileLifecycleTest, create_spec_list_remove) {
    std::filesystem::path location_path = std::filesystem::temp_directory_path() /
                                 "test_objects";
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string location = location_uri.str();
    std::string target = rawstd::URI(location_uri, "00000000-0000-7000-8000-000000000000").str();

    RawstorObjectSpec spec{.size = 1ull << 20};
    int res = rawstor_object_create(target.c_str(), &spec);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    // res = rawstor_object_list(location.c_str(), )

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_default_spec_list_remove) {
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    RawstorObjectSpec spec{.size = 1ull << 20};
    int res = rawstor_object_create_at(
        location.c_str(), nullptr, &spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);

    RawstorObjectSpec read_spec = {};
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    // res = rawstor_object_list(location.c_str(), )

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_spec_list_remove) {
    std::filesystem::path location_path =
        std::filesystem::temp_directory_path() / "test_objects";
    std::ostringstream oss;
    oss << "file://" << location_path.string();
    rawstd::URI location_uri(oss.str());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000002";
    std::string target(65536, '\0');

    RawstorObjectSpec spec{.size = 1ull << 20};
    int res = rawstor_object_create_at(
        location.c_str(), uuid.c_str(), &spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);
    EXPECT_EQ(target, rawstd::URI(location_uri, uuid).str());

    RawstorObjectSpec read_spec = {};
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    // res = rawstor_object_list(location.c_str(), )

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(OstLifecycleTest, create_spec_list_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string uuid = "00000000-0000-7000-8000-000000000003";
    std::string target = rawstd::URI(location_uri, uuid).str();

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectSpec spec{.size = 1ull << 20};

        int res = rawstor_object_create(target.c_str(), &spec);
        EXPECT_EQ(res, 0);
    }

    {
        RawstorObjectSpec read_spec;
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        EXPECT_EQ(res, 0);
        // rawstor_object_spec emulated
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 30));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

TEST(OstLifecycleTest, create_at_default_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectSpec spec{.size = 1ull << 20};

        int res = rawstor_object_create_at(
            location.c_str(), nullptr, &spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
    }

    {
        RawstorObjectSpec read_spec = {};
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        EXPECT_EQ(res, 0);
        // rawstor_object_spec emulated
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 30));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

TEST(OstLifecycleTest, create_at_spec_remove) {
    rawstor::tests::Server server(8753, 256);

    rawstd::URI location_uri("ost://127.0.0.1:8753");
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000004";
    std::string target(65536, '\0');

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    {
        RawstorObjectSpec spec{.size = 1ull << 20};

        int res = rawstor_object_create_at(
            location.c_str(), uuid.c_str(), &spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
        EXPECT_EQ(target, rawstd::URI(location_uri, uuid).str());
    }

    {
        RawstorObjectSpec read_spec = {};
        int res = rawstor_object_spec(target.c_str(), &read_spec);
        EXPECT_EQ(res, 0);
        // rawstor_object_spec emulated
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 30));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

} // unnamed namespace
