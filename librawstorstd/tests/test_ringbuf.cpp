#include "rawstorstd/ringbuf.hpp"

#include <gtest/gtest.h>

#include <memory>
#include <stdexcept>

#include <cerrno>
#include <cstdio>
#include <cstdlib>

namespace {

TEST(RingBufTest, empty) {
    rawstor::RingBuf<int> buf(3);

    EXPECT_THROW(buf.pop(), std::out_of_range);

    EXPECT_TRUE(buf.empty());
    EXPECT_FALSE(buf.full());
    EXPECT_EQ(buf.size(), (size_t)0);
    EXPECT_EQ(buf.capacity(), (size_t)3);
}

TEST(RingBufTest, invalid) {
    rawstor::RingBuf<int> buf(0);

    EXPECT_TRUE(buf.empty());
    EXPECT_TRUE(buf.full());

    std::unique_ptr<int> i = std::make_unique<int>(1);

    EXPECT_THROW(buf.push(std::move(i)), std::system_error);
    EXPECT_THROW(buf.pop(), std::out_of_range);
}

TEST(RingBufTest, basics) {
    rawstor::RingBuf<int> buf(3);

    EXPECT_EQ(buf.size(), (size_t)0);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_TRUE(buf.empty());
    EXPECT_FALSE(buf.full());

    std::unique_ptr<int> i1 = std::make_unique<int>(1);
    buf.push(std::move(i1));
    EXPECT_EQ(buf.size(), (size_t)1);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_FALSE(buf.empty());
    EXPECT_FALSE(buf.full());

    std::unique_ptr<int> i2 = std::make_unique<int>(2);
    buf.push(std::move(i2));
    EXPECT_EQ(buf.size(), (size_t)2);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_FALSE(buf.empty());
    EXPECT_FALSE(buf.full());

    std::unique_ptr<int> i3 = std::make_unique<int>(3);
    buf.push(std::move(i3));
    EXPECT_EQ(buf.size(), (size_t)3);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_FALSE(buf.empty());
    EXPECT_TRUE(buf.full());

    std::unique_ptr<int> i4 = std::make_unique<int>(4);
    EXPECT_THROW(buf.push(std::move(i4)), std::system_error);
    EXPECT_EQ(buf.size(), (size_t)3);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_FALSE(buf.empty());
    EXPECT_TRUE(buf.full());

    std::unique_ptr<int> i;

    EXPECT_EQ(buf.tail(), 1);
    i = buf.pop();
    EXPECT_EQ(*i, 1);
    EXPECT_EQ(buf.size(), (size_t)2);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_FALSE(buf.empty());
    EXPECT_FALSE(buf.full());

    EXPECT_EQ(buf.tail(), 2);
    i = buf.pop();
    EXPECT_EQ(*i, 2);
    EXPECT_EQ(buf.size(), (size_t)1);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_FALSE(buf.empty());
    EXPECT_FALSE(buf.full());

    EXPECT_EQ(buf.tail(), 3);
    i = buf.pop();
    EXPECT_EQ(*i, 3);
    EXPECT_EQ(buf.size(), (size_t)0);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_TRUE(buf.empty());
    EXPECT_FALSE(buf.full());

    EXPECT_THROW(buf.pop(), std::out_of_range);
    EXPECT_EQ(buf.size(), (size_t)0);
    EXPECT_EQ(buf.capacity(), (size_t)3);
    EXPECT_TRUE(buf.empty());
    EXPECT_FALSE(buf.full());
}

TEST(RingBufTest, overlap) {
    rawstor::RingBuf<int> buf(4);

    EXPECT_EQ(buf.size(), (size_t)0);

    std::unique_ptr<int> i1 = std::make_unique<int>(1);
    buf.push(std::move(i1));
    EXPECT_EQ(buf.size(), (size_t)1);

    std::unique_ptr<int> i2 = std::make_unique<int>(2);
    buf.push(std::move(i2));
    EXPECT_EQ(buf.size(), (size_t)2);

    std::unique_ptr<int> i3 = std::make_unique<int>(3);
    buf.push(std::move(i3));
    EXPECT_EQ(buf.size(), (size_t)3);

    std::unique_ptr<int> i4 = std::make_unique<int>(4);
    buf.push(std::move(i4));
    EXPECT_EQ(buf.size(), (size_t)4);

    buf.pop();
    EXPECT_EQ(buf.size(), (size_t)3);

    std::unique_ptr<int> i5 = std::make_unique<int>(5);
    buf.push(std::move(i5));
    EXPECT_EQ(buf.size(), (size_t)4);

    buf.pop();
    EXPECT_EQ(buf.size(), (size_t)3);

    std::unique_ptr<int> i6 = std::make_unique<int>(6);
    buf.push(std::move(i6));
    EXPECT_EQ(buf.size(), (size_t)4);
}

TEST(RingBufTest, move_constructor) {
    rawstor::RingBuf<int> buf1(3);

    std::unique_ptr<int> i1 = std::make_unique<int>(1);
    buf1.push(std::move(i1));
    EXPECT_EQ(buf1.size(), (size_t)1);

    rawstor::RingBuf<int> buf2(std::move(buf1));
    EXPECT_EQ(buf1.size(), (size_t)0);
    EXPECT_EQ(buf1.capacity(), (size_t)0);
    EXPECT_EQ(buf2.size(), (size_t)1);
    EXPECT_EQ(buf2.capacity(), (size_t)3);

    std::unique_ptr<int> i2 = buf2.pop();
    EXPECT_EQ(*i2, 1);
}

TEST(RingBufTest, move_operator) {
    rawstor::RingBuf<int> buf1(3);

    std::unique_ptr<int> i1 = std::make_unique<int>(1);
    buf1.push(std::move(i1));
    EXPECT_EQ(buf1.size(), (size_t)1);

    rawstor::RingBuf<int> buf2(10);
    EXPECT_EQ(buf2.size(), (size_t)0);
    EXPECT_EQ(buf2.capacity(), (size_t)10);

    buf2 = std::move(buf1);

    EXPECT_EQ(buf1.size(), (size_t)0);
    EXPECT_EQ(buf1.capacity(), (size_t)0);
    EXPECT_EQ(buf2.size(), (size_t)1);
    EXPECT_EQ(buf2.capacity(), (size_t)3);

    std::unique_ptr<int> i2 = buf2.pop();
    EXPECT_EQ(*i2, 1);
}

} // unnamed namespace
