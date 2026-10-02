#include "rawstd/hash.h"

#include "config.h"

#include <gtest/gtest.h>

#include <bit>
#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

TEST(HashTest, scalar) {
    const char* buf = "hello world";
    uint64_t hash = rawstd_hash_scalar(buf, strlen(buf));
#ifdef RAWSTOR_WITH_LIBXXHASH
    EXPECT_EQ(hash, 0xd447b1ea40e6988b);
#else
    EXPECT_EQ(hash, static_cast<uint64_t>(0));
#endif
}

TEST(HashTest, vector) {
    const char* s1 = "hello";
    const char* s2 = " ";
    const char* s3 = "world";
    const iovec iov[] = {
        {
            .iov_base = const_cast<char*>(s1),
            .iov_len = strlen(s1),
        },
        {
            .iov_base = const_cast<char*>(s2),
            .iov_len = strlen(s2),
        },
        {
            .iov_base = const_cast<char*>(s3),
            .iov_len = strlen(s3),
        }
    };
    uint64_t hash;
    int res = rawstd_hash_vector(iov, 3, &hash);
    EXPECT_EQ(res, 0);
#ifdef RAWSTOR_WITH_LIBXXHASH
    EXPECT_EQ(hash, 0xd447b1ea40e6988b);
#else
    EXPECT_EQ(hash, static_cast<uint64_t>(0));
#endif
}

TEST(HashTest, stable) {
    const char* buf = "hello world";
    // The same value with or without libxxhash.
    EXPECT_EQ(rawstd_hash_stable(buf, strlen(buf)), 0x7c6d8c019b6ee5d5ull);
    EXPECT_EQ(rawstd_hash_stable(nullptr, 0), 0xefd01f60ba992926ull);
}

TEST(HashTest, stable_spreads_similar_keys) {
    // Keys differing in their last byte only, as consecutive ids do.
    constexpr unsigned keys = 4096;
    constexpr unsigned buckets = 16;
    unsigned counts[buckets] = {};
    double flipped = 0;
    uint64_t previous = 0;
    for (unsigned i = 0; i < keys; ++i) {
        unsigned char key[16] = {};
        key[14] = static_cast<unsigned char>(i >> 8);
        key[15] = static_cast<unsigned char>(i);
        uint64_t hash = rawstd_hash_stable(key, sizeof(key));
        ++counts[hash >> 60];
        if (i != 0) {
            flipped += std::popcount(hash ^ previous);
        }
        previous = hash;
    }
    for (unsigned count : counts) {
        EXPECT_GT(count, keys / buckets * 3 / 4);
        EXPECT_LT(count, keys / buckets * 5 / 4);
    }
    // About half of the bits change between neighbouring keys.
    double average = flipped / (keys - 1);
    EXPECT_GT(average, 28.0);
    EXPECT_LT(average, 36.0);
}

} // unnamed namespace
