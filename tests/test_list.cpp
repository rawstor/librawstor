#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/list.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

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
    void* marker = nullptr;
    int res = rawstor_object_list(location.str().c_str(), 0, &targets, &marker);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(0));

        const char** it = rawstor_string_list_iter(targets);
        EXPECT_EQ(it, nullptr);

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(marker, nullptr);
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
    void* marker = nullptr;
    res = rawstor_object_list(locations.c_str(), 0, &targets, &marker);
    EXPECT_EQ(res, 0);
    if (res == 0) {
        EXPECT_EQ(rawstor_string_list_size(targets), static_cast<size_t>(3));

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

        rawstor_string_list_delete(targets);
    }
    EXPECT_EQ(marker, nullptr);

    res = rawstor_object_remove(target11.str().c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target12.str().c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target22.str().c_str());
    EXPECT_EQ(res, 0);
    res = rawstor_object_remove(target23.str().c_str());
    EXPECT_EQ(res, 0);
}

} // unnamed namespace
