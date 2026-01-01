#include "rawstorstd/hash.h"

#include "config.h"

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

TEST(HashTest, scalar) {
    const char* buf = "hello world";
    uint64_t hash = rawstor_hash_scalar((void*)buf, strlen(buf));
#ifdef RAWSTOR_WITH_LIBXXHASH
    EXPECT_EQ(hash, 0xd447b1ea40e6988b);
#else
    EXPECT_EQ(hash, 0);
#endif
}

TEST(HashTest, vector) {
    iovec iov[] = {
        (iovec){
            .iov_base = (void*)"hello",
            .iov_len = strlen("hello"),
        },
        (iovec){
            .iov_base = (void*)" ",
            .iov_len = strlen(" "),
        },
        (iovec){
            .iov_base = (void*)"world",
            .iov_len = strlen("world"),
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
