#include "rawstorstd/mempool.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>

namespace {

struct MemPoolTest {
    int i1;
    int i2;
};

TEST(MempoolTest, alloc) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    *v1 = 1;

    int* v2 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    *v2 = 2;

    int* v3 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    *v3 = 3;

    rawstor_mempool_free(p, v1);
    rawstor_mempool_free(p, v2);
    rawstor_mempool_free(p, v3);

    rawstor_mempool_delete(p);
}

TEST(MempoolTest, free) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    rawstor_mempool_alloc(p);

    rawstor_mempool_alloc(p);

    int* v3 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);

    rawstor_mempool_free(p, v3);

    int* v3a = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3a, nullptr);
    EXPECT_EQ(v3a, v3);

    rawstor_mempool_delete(p);
}

TEST(MempoolTest, create) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    EXPECT_EQ(rawstor_mempool_capacity(p), (size_t)3);

    EXPECT_EQ(rawstor_mempool_object_size(p), sizeof(int));

    rawstor_mempool_delete(p);
}

TEST(MempoolTest, data) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    *v1 = 1;

    int* v2 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    *v2 = 2;

    int* v3 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    *v3 = 3;

    int* data = static_cast<int*>(rawstor_mempool_data(p));
    EXPECT_EQ(data[0], 1);
    EXPECT_EQ(data[1], 2);
    EXPECT_EQ(data[2], 3);

    rawstor_mempool_delete(p);
}

TEST(MempoolTest, order) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    int* v2 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    int* v3 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);

    rawstor_mempool_free(p, v2);
    rawstor_mempool_free(p, v3);
    rawstor_mempool_free(p, v1);

    int* v1a = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v1a, nullptr);
    EXPECT_EQ(v1a, v1);

    int* v3a = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3a, nullptr);
    EXPECT_EQ(v3a, v3);

    int* v2a = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v2a, nullptr);
    EXPECT_EQ(v2a, v2);

    rawstor_mempool_delete(p);
}

TEST(MempoolTest, counters) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(MemPoolTest));
    EXPECT_NE(p, nullptr);

    EXPECT_EQ(rawstor_mempool_available(p), (size_t)3);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)0);

    MemPoolTest* v1 = static_cast<MemPoolTest*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    EXPECT_EQ(rawstor_mempool_available(p), (size_t)2);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)1);

    MemPoolTest* v2 = static_cast<MemPoolTest*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    EXPECT_EQ(rawstor_mempool_available(p), (size_t)1);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)2);

    MemPoolTest* v3 = static_cast<MemPoolTest*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    EXPECT_EQ(rawstor_mempool_available(p), (size_t)0);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)3);

    rawstor_mempool_free(p, v3);
    EXPECT_EQ(rawstor_mempool_available(p), (size_t)1);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)2);

    rawstor_mempool_free(p, v2);
    EXPECT_EQ(rawstor_mempool_available(p), (size_t)2);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)1);

    rawstor_mempool_free(p, v1);
    EXPECT_EQ(rawstor_mempool_available(p), (size_t)3);
    EXPECT_EQ(rawstor_mempool_allocated(p), (size_t)0);

    rawstor_mempool_delete(p);
}

TEST(MempoolTest, overflow) {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    int* v2 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    int* v3 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    int* v4 = static_cast<int*>(rawstor_mempool_alloc(p));
    EXPECT_EQ(v4, nullptr);
    EXPECT_EQ(errno, ENOBUFS);

    rawstor_mempool_delete(p);
}

} // unnamed namespace
