#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include "rawio_sync.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstring>
#include <memory>

namespace {

ssize_t target_create(
    rawio::Queue& queue, const std::string& target,
    const RawstorObjectSpec& spec
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_create(&queue, target.c_str(), &spec, cb, data);
    });
}

ssize_t target_spec(
    rawio::Queue& queue, const std::string& target, RawstorObjectSpec* spec
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_spec(&queue, target.c_str(), spec, cb, data);
    });
}

ssize_t target_remove(rawio::Queue& queue, const std::string& target) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_target_remove(&queue, target.c_str(), cb, data);
    });
}

ssize_t location_list(
    rawio::Queue& queue, const std::string& location, unsigned int limit,
    RawstorStringList** targets, RawstorPaginationToken* token
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_list(
            &queue, location.c_str(), limit, targets, token, cb, data
        );
    });
}

ssize_t location_create(
    rawio::Queue& queue, const std::string& location, const char* uuid,
    const RawstorObjectSpec& spec, char* target, size_t size
) {
    return rawstor::tests::sync_run(&queue, [&](auto cb, void* data) {
        return rawstor_location_create(
            &queue, location.c_str(), uuid, &spec, target, size, cb, data
        );
    });
}

TEST(FileLifecycleTest, create_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{.size = 1ull << 20};
    ssize_t res = target_create(*queue, target, spec);
    EXPECT_EQ(res, 0);

    RawstorObjectSpec read_spec;
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = location_list(*queue, location, 0, &targets, &token);
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

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

// A failed create() must only roll back what THIS call itself created --
// a second create() on an already-existing target fails with EEXIST, and
// must not remove() the target the first call created.
TEST(FileLifecycleTest, create_twice_preserves_existing) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string uuid = "00000000-0000-7000-8000-000000000001";
    std::string target = rawstd::URI(location_uri, uuid).str();

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{.size = 1ull << 20};
    ssize_t res = target_create(*queue, target, spec);
    EXPECT_EQ(res, 0);

    res = target_create(*queue, target, spec);
    EXPECT_EQ(res, -EEXIST);

    RawstorObjectSpec read_spec;
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_default_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string target(65536, '\0');

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{.size = 1ull << 20};
    ssize_t res = location_create(
        *queue, location, nullptr, spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);

    RawstorObjectSpec read_spec = {};
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = location_list(*queue, location, 0, &targets, &token);
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

    res = target_remove(*queue, target);
    EXPECT_EQ(res, 0);
}

TEST(FileLifecycleTest, create_at_spec_list_remove) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location_uri(dir.uri());
    std::string location = location_uri.str();
    std::string uuid = "00000000-0000-7000-8000-000000000002";
    std::string target(65536, '\0');

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorObjectSpec spec{.size = 1ull << 20};
    ssize_t res = location_create(
        *queue, location, uuid.c_str(), spec, target.data(), target.size()
    );
    ASSERT_GT(res, 0);
    ASSERT_LT((size_t)res, target.size());
    target.resize(res);
    EXPECT_EQ(target, rawstd::URI(location_uri, uuid).str());

    RawstorObjectSpec read_spec = {};
    res = target_spec(*queue, target, &read_spec);
    EXPECT_EQ(res, 0);
    EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = location_list(*queue, location, 0, &targets, &token);
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

    res = target_remove(*queue, target);
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

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    {
        RawstorObjectSpec spec{.size = 1ull << 20};

        ssize_t res = target_create(*queue, target, spec);
        EXPECT_EQ(res, 0);
    }

    {
        RawstorObjectSpec read_spec;
        ssize_t res = target_spec(*queue, target, &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        ssize_t res = target_remove(*queue, target);
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

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    {
        RawstorObjectSpec spec{.size = 1ull << 20};

        ssize_t res = location_create(
            *queue, location, nullptr, spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
    }

    {
        RawstorObjectSpec read_spec = {};
        ssize_t res = target_spec(*queue, target, &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        ssize_t res = target_remove(*queue, target);
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

    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    {
        RawstorObjectSpec spec{.size = 1ull << 20};

        ssize_t res = location_create(
            *queue, location, uuid.c_str(), spec, target.data(), target.size()
        );
        ASSERT_GT(res, 0);
        ASSERT_LT((size_t)res, target.size());
        target.resize(res);
        EXPECT_EQ(target, rawstd::URI(location_uri, uuid).str());
    }

    {
        RawstorObjectSpec read_spec = {};
        ssize_t res = target_spec(*queue, target, &read_spec);
        EXPECT_EQ(res, 0);
        EXPECT_EQ(read_spec.size, (size_t)(1ull << 20));
    }

    {
        ssize_t res = target_remove(*queue, target);
        EXPECT_EQ(res, 0);
    }
}

} // unnamed namespace
