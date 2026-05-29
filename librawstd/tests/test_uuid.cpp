#include "rawstd/uuid.h"
#include "uuid_internals.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <unistd.h>

namespace {

TEST(UUIDTest, timestamp) {
    RawstdUUID uuid;
    EXPECT_EQ(rawstd_uuid7_set_timestamp(&uuid, 100), 0);
    EXPECT_EQ(rawstd_uuid7_get_timestamp(&uuid), (uint64_t)100);
    EXPECT_EQ(rawstd_uuid7_set_timestamp(&uuid, (1ull << 48) - 1), 0);
    EXPECT_EQ(rawstd_uuid7_get_timestamp(&uuid), (1ull << 48) - 1);
    EXPECT_EQ(rawstd_uuid7_set_timestamp(&uuid, (1ull << 48)), -ERANGE);
    EXPECT_EQ(rawstd_uuid7_get_timestamp(&uuid), (1ull << 48) - 1);
}

TEST(UUIDTest, counter) {
    RawstdUUID uuid;
    EXPECT_EQ(rawstd_uuid7_set_counter(&uuid, 100), 0);
    EXPECT_EQ(rawstd_uuid7_get_counter(&uuid), (uint64_t)100);
    EXPECT_EQ(rawstd_uuid7_set_counter(&uuid, (1ull << 42) - 1), 0);
    EXPECT_EQ(rawstd_uuid7_get_counter(&uuid), (1ull << 42) - 1);
    EXPECT_EQ(rawstd_uuid7_set_counter(&uuid, (1ull << 42)), -ERANGE);
    EXPECT_EQ(rawstd_uuid7_get_counter(&uuid), (1ull << 42) - 1);
}

TEST(UUIDTest, version) {
    for (int version = 0; version < 16; ++version) {
        RawstdUUID uuid;
        rawstd_uuid_set_version(&uuid, version);
        EXPECT_EQ(rawstd_uuid_get_version(&uuid), version);
    }
}

TEST(UUIDTest, variant) {
    for (int variant = 0; variant < 4; ++variant) {
        RawstdUUID uuid;
        rawstd_uuid_set_variant(&uuid, variant);
        EXPECT_EQ(rawstd_uuid_get_variant(&uuid), variant);
    }
}

TEST(UUIDTest, all_at_once) {
    RawstdUUIDString s;
    RawstdUUID uuid = {0};
    rawstd_uuid_set_version(&uuid, 7);
    rawstd_uuid_set_variant(&uuid, 2);
    rawstd_uuid7_set_counter(&uuid, (1ull << 42) - 1);
    rawstd_uuid7_set_timestamp(&uuid, (1ull << 48) - 1);

    EXPECT_EQ(rawstd_uuid_get_version(&uuid), 7);
    EXPECT_EQ(rawstd_uuid_get_variant(&uuid), 2);
    EXPECT_EQ(rawstd_uuid7_get_counter(&uuid), (1ull << 42) - 1);
    EXPECT_EQ(rawstd_uuid7_get_timestamp(&uuid), (1ull << 48) - 1);

    rawstd_uuid_to_string(&uuid, &s);
    EXPECT_EQ(strcmp(s, "ffffffff-ffff-7fff-bfff-ffff00000000"), 0);
}

TEST(UUIDTest, init) {
    RawstdUUID uuid;
    EXPECT_EQ(rawstd_uuid7_init(&uuid), 0);

    EXPECT_EQ(rawstd_uuid_get_version(&uuid), 7);
    EXPECT_EQ(rawstd_uuid_get_variant(&uuid), 2);
}

TEST(UUIDTest, from_string) {
    RawstdUUID uuid;
    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800ec"),
        0
    );

    EXPECT_EQ(rawstd_uuid_get_version(&uuid), 7);
    EXPECT_EQ(rawstd_uuid_get_variant(&uuid), 2);
    EXPECT_EQ(rawstd_uuid7_get_timestamp(&uuid), 1743336192936ul);
    EXPECT_EQ(rawstd_uuid7_get_counter(&uuid), 1131440955435ul);
}

TEST(UUIDTest, from_string_errors) {
    RawstdUUID uuid;
    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800ec"),
        0
    );

    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "0195E6EF-3BA8-741D-AF22-E02BF9C800EC"),
        0
    );

    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800ecX"),
        0
    );

    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "0195e6efX3ba8-741d-af22-e02bf9c800ec"),
        -EINVAL
    );

    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "0195e6ef-3ba8-741d-af22-e02bf9c800e"),
        -EINVAL
    );

    EXPECT_EQ(
        rawstd_uuid_from_string(&uuid, "X195e6ef-3ba8-741d-af22-e02bf9c800ec"),
        -EINVAL
    );
}

} // unnamed namespace
