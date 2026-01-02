#include "rawstorstd/list.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <cstdlib>

namespace {

TEST(ListTest, empty) {
    RawstorList* l = rawstor_list_create(sizeof(int));

    void* it = rawstor_list_iter(l);
    EXPECT_EQ(it, nullptr);

    EXPECT_NE(rawstor_list_empty(l), 0);
    EXPECT_EQ(rawstor_list_size(l), (size_t)0);

    rawstor_list_delete(l);
}

TEST(ListTest, append) {
    int* it;
    RawstorList* l = rawstor_list_create(sizeof(int));

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    EXPECT_EQ(rawstor_list_empty(l), 0);
    EXPECT_EQ(rawstor_list_size(l), (size_t)1);

    rawstor_list_delete(l);
}

TEST(ListTest, iter) {
    int* it;
    RawstorList* l = rawstor_list_create(sizeof(int));

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 3;

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 3);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstor_list_delete(l);
}

TEST(ListTest, remove) {
    int* it;
    RawstorList* l = rawstor_list_create(sizeof(int));

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 3;

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstor_list_remove(l, it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 3);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstor_list_delete(l);
}

TEST(ListTest, remove_first) {
    int* it;
    RawstorList* l = rawstor_list_create(sizeof(int));

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstor_list_remove(l, it));
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstor_list_delete(l);
}

TEST(ListTest, remove_last) {
    int* it;
    RawstorList* l = rawstor_list_create(sizeof(int));

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstor_list_remove(l, it));
    EXPECT_EQ(it, nullptr);

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_EQ(it, nullptr);

    rawstor_list_delete(l);
}

TEST(ListTest, size) {
    int* it;
    RawstorList* l = rawstor_list_create(sizeof(int));

    EXPECT_EQ(rawstor_list_size(l), (size_t)0);

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 1;

    EXPECT_EQ(rawstor_list_size(l), (size_t)1);

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 2;

    EXPECT_EQ(rawstor_list_size(l), (size_t)2);

    it = static_cast<int*>(rawstor_list_append(l));
    EXPECT_NE(it, nullptr);
    *it = 3;

    EXPECT_EQ(rawstor_list_size(l), (size_t)3);

    it = static_cast<int*>(rawstor_list_iter(l));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 1);

    it = static_cast<int*>(rawstor_list_next(it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 2);

    it = static_cast<int*>(rawstor_list_remove(l, it));
    EXPECT_NE(it, nullptr);
    EXPECT_EQ(*it, 3);

    EXPECT_EQ(rawstor_list_size(l), (size_t)2);

    rawstor_list_delete(l);
}

} // unnamed namespace
