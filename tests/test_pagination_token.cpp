#include <rawstor/rawstor.h>

#include <gtest/gtest.h>

namespace {

TEST(PaginationTokenTest, empty) {
    RawstorPaginationToken token = {};
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));

    token.bytes[1] = 1;
    EXPECT_FALSE(rawstor_pagination_token_empty(&token));

    memset(token.bytes, 0, sizeof(token.bytes));
    EXPECT_TRUE(rawstor_pagination_token_empty(&token));
}

} // unnamed namespace
