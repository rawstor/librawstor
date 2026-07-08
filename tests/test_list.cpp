#include "server.hpp"
#include "session.hpp"

#include "opts.h"

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <string>

namespace {

rawstd::URI get_location_uri(const std::string& name) {
    std::filesystem::path path = std::filesystem::temp_directory_path() / name;
    std::ostringstream oss;
    oss << "file://" << path.string();
    return rawstd::URI(oss.str());
}

TEST(ListTest, empty) {
    rawstd::URI location = get_location_uri("test_objects");

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
    rawstd::URI location1 = get_location_uri("test_objects1");
    rawstd::URI location2 = get_location_uri("test_objects2");

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
    rawstd::URI location = get_location_uri("test_objects");

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
    printf("etalon targets {\n");
    for (const auto& target : targets) {
        printf("%s\n", target.c_str());
    }
    printf("etalon targets }\n");

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
            printf("page[%zu] = %s\n", i, *it);
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

} // unnamed namespace
