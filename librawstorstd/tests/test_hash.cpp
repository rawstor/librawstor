#include "rawstorstd/hash.h"

#include "config.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

TEST(HashTest, scalar) {
    const char* buf = "hello world";
    uint64_t hash = rawstor_hash_scalar(const_cast<char*>(buf), strlen(buf));
#ifdef RAWSTOR_WITH_LIBXXHASH
    EXPECT_EQ(hash, 0xd447b1ea40e6988b);
#else
    EXPECT_EQ(hash, 0);
#endif
}

TEST(HashTest, vector) {
    const char* s1 = "hello";
    const char* s2 = " ";
    const char* s3 = "world";
    iovec iov[] = {
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
    int res = rawstor_hash_vector(iov, 3, &hash);
    EXPECT_EQ(res, 0);
#ifdef RAWSTOR_WITH_LIBXXHASH
    EXPECT_EQ(hash, 0xd447b1ea40e6988b);
#else
    EXPECT_EQ(hash, 0);
#endif
}

} // unnamed namespace
