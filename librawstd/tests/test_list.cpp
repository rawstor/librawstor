#include "rawstd/list.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdlib>

namespace {

TEST(ListTest, empty) {
    RawstdList* l = rawstd_list_create(sizeof(int));

    void* it = rawstd_list_iter(l);
    EXPECT_EQ(it, nullptr);

    EXPECT_NE(rawstd_list_empty(l), 0);
    EXPECT_EQ(rawstd_list_size(l), (size_t)0);

    rawstd_list_delete(l);
}

TEST(ListTest, append) {
    int* it;
    RawstdList* l = rawstd_list_create(sizeof(int));

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    EXPECT_EQ(rawstd_list_empty(l), 0);
    EXPECT_EQ(rawstd_list_size(l), (size_t)1);

    rawstd_list_delete(l);
}

TEST(ListTest, iter) {
    int* it;
    RawstdList* l = rawstd_list_create(sizeof(int));

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 3;

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 3);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstd_list_delete(l);
}

TEST(ListTest, remove) {
    int* it;
    RawstdList* l = rawstd_list_create(sizeof(int));

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 3;

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstd_list_remove(l, it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 3);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstd_list_delete(l);
}

TEST(ListTest, remove_first) {
    int* it;
    RawstdList* l = rawstd_list_create(sizeof(int));

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstd_list_remove(l, it));
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstd_list_delete(l);
}

TEST(ListTest, remove_last) {
    int* it;
    RawstdList* l = rawstd_list_create(sizeof(int));

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstd_list_remove(l, it));
    EXPECT_EQ(it, nullptr);

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstd_list_delete(l);
}

TEST(ListTest, size) {
    int* it;
    RawstdList* l = rawstd_list_create(sizeof(int));

    EXPECT_EQ(rawstd_list_size(l), (size_t)0);

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    EXPECT_EQ(rawstd_list_size(l), (size_t)1);

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    EXPECT_EQ(rawstd_list_size(l), (size_t)2);

    it = static_cast<int*>(rawstd_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 3;

    EXPECT_EQ(rawstd_list_size(l), (size_t)3);

    it = static_cast<int*>(rawstd_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstd_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstd_list_remove(l, it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 3);

    EXPECT_EQ(rawstd_list_size(l), (size_t)2);

    rawstd_list_delete(l);
}

} // unnamed namespace
