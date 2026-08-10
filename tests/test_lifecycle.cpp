#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <cstring>

namespace {

TEST(FileLifecycleTest, create_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    RawstorObjectSpec spec{.size = 1ull << 20};
    int res = rawstor_object_create(target.c_str(), &spec);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec read_spec;
    res = rawstor_object_spec(target.c_str(), &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_default_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
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

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

    res = rawstor_object_remove(target.c_str());
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
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

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(location.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(1));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_NE(it, nullptr);
        if (it != nullptr) {
            EXPECT_EQ(target, *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(rawstor_pagination_token_empty(&token), 1);

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
        s.cmd_spec(RAWSTOR_MAGIC, 0, RawstorObjectSpec{.size = 1ull << 20});
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
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
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
        s.cmd_spec(RAWSTOR_MAGIC, 0, RawstorObjectSpec{.size = 1ull << 20});
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
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
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
        s.cmd_spec(RAWSTOR_MAGIC, 0, RawstorObjectSpec{.size = 1ull << 20});
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
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

} // unnamed namespace
