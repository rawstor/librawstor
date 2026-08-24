#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include "connection.hpp"
#include "opts.h"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>

namespace {

// Duplicate of object.cpp's own `run()` -- see that one's doc comment for
// why it isn't shared.
template <typename T>
T run(rawio::Queue& q, rawstd::Task<T> t) {
    while (!t.done()) {
        q.wait_timeout(rawstor_opts_tcp_user_timeout());
    }
    return t.get();
}

TEST(ListTest, empty) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    int res = rawstor_object_list(location.str().c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(0));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_EQ(it, nullptr);

        rawstor_string_list_delete(targets);
    }
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));
}

TEST(ListTest, merge) {
    rawstor::tests::TmpDir dir1;
    rawstor::tests::TmpDir dir2;
    rawstd::URI location1(dir1.uri());
    rawstd::URI location2(dir2.uri());

    rawstd::URI target11 =
        rawstd::URI(location1, "00000000-0000-7000-8000-000000000001");
    rawstd::URI target12 =
        rawstd::URI(location1, "00000000-0000-7000-8000-000000000002");
    rawstd::URI target22 =
        rawstd::URI(location2, "00000000-0000-7000-8000-000000000002");
    rawstd::URI target23 =
        rawstd::URI(location2, "00000000-0000-7000-8000-000000000003");

    int res;
    RawstorObjectSpec spec{.size = 1ull << 20};
    res = rawstor_object_create(target11.str().c_str(), &spec);
    ASSERT_EQ(res, 0);
    res = rawstor_object_create(target12.str().c_str(), &spec);
    ASSERT_EQ(res, 0);
    res = rawstor_object_create(target22.str().c_str(), &spec);
    ASSERT_EQ(res, 0);
    res = rawstor_object_create(target23.str().c_str(), &spec);
    ASSERT_EQ(res, 0);

    std::string locations = rawstd::URI::uris({location1, location2});

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    res = rawstor_object_list(locations.c_str(), 0, &targets, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(3));

        if (rawstor_string_list_size(targets) == 3) {
            const char** it = rawstor_string_list_iter(targets);
            EXPECT_NE(it, nullptr);
            EXPECT_EQ(rawstd::URI::uris({target11}), *it);

            it = rawstor_string_list_next(it);
            EXPECT_NE(it, nullptr);
            EXPECT_EQ(rawstd::URI::uris({target12, target22}), *it);

            it = rawstor_string_list_next(it);
            EXPECT_NE(it, nullptr);
            EXPECT_EQ(rawstd::URI::uris({target23}), *it);

            it = rawstor_string_list_next(it);
            EXPECT_EQ(it, nullptr);
        }

        rawstor_string_list_delete(targets);
    }
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));

    res = rawstor_object_remove(target11.str().c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target12.str().c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target22.str().c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target23.str().c_str());
    EXPECT_EQ(res, 0);
}

TEST(ListTest, pagination) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());

    {
        RawstorStringList* page;
        RawstorPaginationToken token = {};
        int res = rawstor_object_list(location.str().c_str(), 0, &page, &token);
        EXPECT_EQ(res, 0);
        if (res == 0) {
            EXPECT_EQ(rawstor_string_list_size(page), static_cast<size_t>(0));
            EXPECT_TRUE(rawstor_pagination_token_empty(&token));

            rawstor_string_list_delete(page);
        }
    }

    unsigned int total = rawstor_opts_list_limit() + 1;

    std::vector<std::string> targets;
    targets.reserve(total);
    for (unsigned int i = 0; i < total; ++i) {
        RawstorObjectSpec spec{.size = 1ull << 10};

        char target[65536];
        int res = rawstor_object_create_at(
            location.str().c_str(), nullptr, &spec, target, sizeof(target)
        );
        EXPECT_GT(res, 0);

        targets.push_back(target);
    }
    std::sort(targets.begin(), targets.end());

    RawstorStringList* page;
    RawstorPaginationToken token = {};
    int res = rawstor_object_list(location.str().c_str(), 0, &page, &token);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(
            rawstor_string_list_size(page),
            static_cast<size_t>(rawstor_opts_list_limit())
        );

        size_t i = 0;
        for (const char** it = rawstor_string_list_iter(page); it != NULL;
             it = rawstor_string_list_next(it), ++i) {
            EXPECT_LT(i, targets.size());
            if (i < targets.size()) {
                EXPECT_EQ(*it, targets[i]);
            }
        }

        rawstor_string_list_delete(page);

        EXPECT_FALSE(rawstor_pagination_token_empty(&token));
        if (!rawstor_pagination_token_empty(&token)) {
            int res =
                rawstor_object_list(location.str().c_str(), 0, &page, &token);
            EXPECT_EQ(res, 0);
            if (res == 0) {
                EXPECT_EQ(
                    rawstor_string_list_size(page), static_cast<size_t>(1)
                );

                const char** it = rawstor_string_list_iter(page);
                EXPECT_NE(it, nullptr);
                if (it != nullptr) {
                    EXPECT_EQ(*it, targets.back());
                }

                it = rawstor_string_list_next(it);
                EXPECT_EQ(it, nullptr);

                rawstor_string_list_delete(page);

                EXPECT_TRUE(rawstor_pagination_token_empty(&token));
            }
        }
    }

    for (const auto& target : targets) {
        int res = rawstor_object_remove(target.c_str());
        EXPECT_EQ(res, 0);
    }
}

// Location::list()/create() and Target::create()/remove()/spec() all use
// a Connection::create()-only, never-open()-ed Connection for their
// metadata work -- unlike a data-path Connection, _object stays null on
// one of these for its whole lifetime. invalidate_session()'s reconnect
// path used to call the replacement session's set_object(_object)
// unconditionally regardless, and every backend's set_object()
// dereferences its Object* argument (e.g. blk::Session::set_object()
// reading object->target()) -- a null-pointer crash the very first time
// a metadata op actually needed to reconnect a session, not something
// any of ListTest's other cases above exercise (they never fail an op
// in the first place).
TEST(ListTest, invalidate_session_on_metadata_only_connection) {
    rawstor::tests::TmpDir dir;
    rawstd::URI location(dir.uri());
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(4);

    std::unique_ptr<rawstor::Connection> cn =
        run(*queue, rawstor::Connection::create(*queue, location, 1));
    std::shared_ptr<rawstor::Session> s = cn->get_next_session();

    EXPECT_NO_THROW(run(*queue, cn->invalidate_session(s)));
}

} // unnamed namespace
