#include "rawstd/mempool.h"

#include <gtest/gtest.h>

#include <cerrno>
#include <cstdlib>

namespace {

struct MemPoolTest {
    int i1;
    int i2;
};

TEST(MempoolTest, alloc) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    *v1 = 1;

    int* v2 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    *v2 = 2;

    int* v3 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    *v3 = 3;

    rawstd_mempool_free(p, v1);
    rawstd_mempool_free(p, v2);
    rawstd_mempool_free(p, v3);

    rawstd_mempool_delete(p);
}

TEST(MempoolTest, free) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    rawstd_mempool_alloc(p);

    rawstd_mempool_alloc(p);

    int* v3 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);

    rawstd_mempool_free(p, v3);

    int* v3a = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3a, nullptr);
    EXPECT_EQ(v3a, v3);

    rawstd_mempool_delete(p);
}

TEST(MempoolTest, create) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    EXPECT_EQ(rawstd_mempool_capacity(p), (size_t)3);

    EXPECT_EQ(rawstd_mempool_object_size(p), sizeof(int));

    rawstd_mempool_delete(p);
}

TEST(MempoolTest, data) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    *v1 = 1;

    int* v2 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    *v2 = 2;

    int* v3 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    *v3 = 3;

    int* data = static_cast<int*>(rawstd_mempool_data(p));
    EXPECT_EQ(data[0], 1);
    EXPECT_EQ(data[1], 2);
    EXPECT_EQ(data[2], 3);

    rawstd_mempool_delete(p);
}

TEST(MempoolTest, order) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    int* v2 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    int* v3 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);

    rawstd_mempool_free(p, v2);
    rawstd_mempool_free(p, v3);
    rawstd_mempool_free(p, v1);

    int* v1a = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v1a, nullptr);
    EXPECT_EQ(v1a, v1);

    int* v3a = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3a, nullptr);
    EXPECT_EQ(v3a, v3);

    int* v2a = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v2a, nullptr);
    EXPECT_EQ(v2a, v2);

    rawstd_mempool_delete(p);
}

TEST(MempoolTest, counters) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(MemPoolTest));
    EXPECT_NE(p, nullptr);

    EXPECT_EQ(rawstd_mempool_available(p), (size_t)3);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)0);

    MemPoolTest* v1 = static_cast<MemPoolTest*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    EXPECT_EQ(rawstd_mempool_available(p), (size_t)2);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)1);

    MemPoolTest* v2 = static_cast<MemPoolTest*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    EXPECT_EQ(rawstd_mempool_available(p), (size_t)1);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)2);

    MemPoolTest* v3 = static_cast<MemPoolTest*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    EXPECT_EQ(rawstd_mempool_available(p), (size_t)0);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)3);

    rawstd_mempool_free(p, v3);
    EXPECT_EQ(rawstd_mempool_available(p), (size_t)1);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)2);

    rawstd_mempool_free(p, v2);
    EXPECT_EQ(rawstd_mempool_available(p), (size_t)2);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)1);

    rawstd_mempool_free(p, v1);
    EXPECT_EQ(rawstd_mempool_available(p), (size_t)3);
    EXPECT_EQ(rawstd_mempool_allocated(p), (size_t)0);

    rawstd_mempool_delete(p);
}

TEST(MempoolTest, overflow) {
    RawstdMemPool* p = rawstd_mempool_create(3, sizeof(int));
    EXPECT_NE(p, nullptr);

    int* v1 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v1, nullptr);
    int* v2 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v2, nullptr);
    int* v3 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_NE(v3, nullptr);
    int* v4 = static_cast<int*>(rawstd_mempool_alloc(p));
    EXPECT_EQ(v4, nullptr);
    EXPECT_EQ(errno, ENOBUFS);

    rawstd_mempool_delete(p);
}

} // unnamed namespace
