#include "rawstd/units.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdint>
#include <string>

namespace {

TEST(UnitsTest, size_to_bytes_basics) {
    uint64_t out = 0;

    EXPECT_EQ(rawstd_size_to_bytes("0B", &out), 0);
    EXPECT_EQ(out, 0u);

    EXPECT_EQ(rawstd_size_to_bytes("1K", &out), 0);
    EXPECT_EQ(out, 1024u);

    EXPECT_EQ(rawstd_size_to_bytes("256M", &out), 0);
    EXPECT_EQ(out, 256ull << 20);

    EXPECT_EQ(rawstd_size_to_bytes("2G", &out), 0);
    EXPECT_EQ(out, 2ull << 30);

    EXPECT_EQ(rawstd_size_to_bytes("3T", &out), 0);
    EXPECT_EQ(out, 3ull << 40);

    EXPECT_EQ(rawstd_size_to_bytes("4P", &out), 0);
    EXPECT_EQ(out, 4ull << 50);

    EXPECT_EQ(rawstd_size_to_bytes("5E", &out), 0);
    EXPECT_EQ(out, 5ull << 60);
}

TEST(UnitsTest, size_to_bytes_case_insensitive) {
    uint64_t out = 0;

    EXPECT_EQ(rawstd_size_to_bytes("2g", &out), 0);
    EXPECT_EQ(out, 2ull << 30);

    EXPECT_EQ(rawstd_size_to_bytes("7b", &out), 0);
    EXPECT_EQ(out, 7u);
}

TEST(UnitsTest, size_to_bytes_missing_unit) {
    uint64_t out = 0;
    EXPECT_EQ(rawstd_size_to_bytes("256", &out), -EINVAL);
}

TEST(UnitsTest, size_to_bytes_invalid_unit) {
    uint64_t out = 0;
    EXPECT_EQ(rawstd_size_to_bytes("256X", &out), -EINVAL);
}

TEST(UnitsTest, size_to_bytes_invalid_number) {
    uint64_t out = 0;
    EXPECT_EQ(rawstd_size_to_bytes("abcM", &out), -EINVAL);
}

TEST(UnitsTest, size_to_bytes_overflow) {
    uint64_t out = 0;
    EXPECT_EQ(rawstd_size_to_bytes("16E", &out), -EOVERFLOW);
}

TEST(UnitsTest, bytes_to_size_picks_largest_exact_unit) {
    char buf[256];

    ASSERT_GT(rawstd_bytes_to_size(256ull << 20, buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "256M");

    ASSERT_GT(rawstd_bytes_to_size(0, buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "0B");

    ASSERT_GT(rawstd_bytes_to_size(1023, buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "1023B");
}

TEST(UnitsTest, bytes_to_size_human_exact) {
    char buf[256];

    ASSERT_GT(rawstd_bytes_to_size_human(1ull << 30, buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "1G");
}

TEST(UnitsTest, bytes_to_size_human_rounds_with_tilde) {
    char buf[256];

    ASSERT_GT(rawstd_bytes_to_size_human(1500000000, buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "~1G");
}

TEST(UnitsTest, bytes_to_size_unit_exact) {
    char buf[256];

    ASSERT_GT(rawstd_bytes_to_size_unit(1ull << 30, 'M', buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "1024M");
}

TEST(UnitsTest, bytes_to_size_unit_invalid_unit) {
    char buf[256];
    EXPECT_EQ(rawstd_bytes_to_size_unit(100, 'X', buf, sizeof(buf)), -EINVAL);
}

TEST(UnitsTest, round_trip) {
    uint64_t out = 0;
    ASSERT_EQ(rawstd_size_to_bytes("42G", &out), 0);

    char buf[256];
    ASSERT_GT(rawstd_bytes_to_size(out, buf, sizeof(buf)), 0);
    EXPECT_STREQ(buf, "42G");
}

} // namespace
