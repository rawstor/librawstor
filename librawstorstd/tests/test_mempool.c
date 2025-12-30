#include "rawstorstd/mempool.h"

#include "unittest.h"

#include <errno.h>
#include <stdlib.h>

struct MemPoolTest {
    int i1;
    int i2;
};

static int test_mempool_alloc() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int* v1 = rawstor_mempool_alloc(p);
    assertTrue(v1 != NULL);
    *v1 = 1;

    int* v2 = rawstor_mempool_alloc(p);
    assertTrue(v2 != NULL);
    *v2 = 2;

    int* v3 = rawstor_mempool_alloc(p);
    assertTrue(v3 != NULL);
    *v3 = 3;

    rawstor_mempool_free(p, v1);
    rawstor_mempool_free(p, v2);
    rawstor_mempool_free(p, v3);

    rawstor_mempool_delete(p);

    return 0;
}

static int test_mempool_free() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    assertTrue(p != NULL);

    rawstor_mempool_alloc(p);

    rawstor_mempool_alloc(p);

    int* v3 = rawstor_mempool_alloc(p);
    assertTrue(v3 != NULL);

    rawstor_mempool_free(p, v3);

    int* v3a = rawstor_mempool_alloc(p);
    assertTrue(v3a != NULL);
    assertTrue(v3a == v3);

    rawstor_mempool_delete(p);

    return 0;
}

static int test_mempool_create() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    assertTrue(p != NULL);

    assertTrue(rawstor_mempool_capacity(p) == 3);

    assertTrue(rawstor_mempool_object_size(p) == sizeof(int));

    rawstor_mempool_delete(p);

    return 0;
}

static int test_mempool_data() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int* v1 = rawstor_mempool_alloc(p);
    assertTrue(v1 != NULL);
    *v1 = 1;

    int* v2 = rawstor_mempool_alloc(p);
    assertTrue(v2 != NULL);
    *v2 = 2;

    int* v3 = rawstor_mempool_alloc(p);
    assertTrue(v3 != NULL);
    *v3 = 3;

    int* data = rawstor_mempool_data(p);
    assertTrue(data[0] == 1);
    assertTrue(data[1] == 2);
    assertTrue(data[2] == 3);

    rawstor_mempool_delete(p);

    return 0;
}

static int test_mempool_order() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int* v1 = rawstor_mempool_alloc(p);
    assertTrue(v1 != NULL);
    int* v2 = rawstor_mempool_alloc(p);
    assertTrue(v2 != NULL);
    int* v3 = rawstor_mempool_alloc(p);
    assertTrue(v3 != NULL);

    rawstor_mempool_free(p, v2);
    rawstor_mempool_free(p, v3);
    rawstor_mempool_free(p, v1);

    int* v1a = rawstor_mempool_alloc(p);
    assertTrue(v1a != NULL);
    assertTrue(v1a == v1);

    int* v3a = rawstor_mempool_alloc(p);
    assertTrue(v3a != NULL);
    assertTrue(v3a == v3);

    int* v2a = rawstor_mempool_alloc(p);
    assertTrue(v2a != NULL);
    assertTrue(v2a == v2);

    rawstor_mempool_delete(p);

    return 0;
}

static int test_mempool_counters() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(struct MemPoolTest));
    assertTrue(p != NULL);

    assertTrue(rawstor_mempool_available(p) == 3);
    assertTrue(rawstor_mempool_allocated(p) == 0);

    struct MemPoolTest* v1 = rawstor_mempool_alloc(p);
    assertTrue(v1 != NULL);
    assertTrue(rawstor_mempool_available(p) == 2);
    assertTrue(rawstor_mempool_allocated(p) == 1);

    struct MemPoolTest* v2 = rawstor_mempool_alloc(p);
    assertTrue(v2 != NULL);
    assertTrue(rawstor_mempool_available(p) == 1);
    assertTrue(rawstor_mempool_allocated(p) == 2);

    struct MemPoolTest* v3 = rawstor_mempool_alloc(p);
    assertTrue(v3 != NULL);
    assertTrue(rawstor_mempool_available(p) == 0);
    assertTrue(rawstor_mempool_allocated(p) == 3);

    rawstor_mempool_free(p, v3);
    assertTrue(rawstor_mempool_available(p) == 1);
    assertTrue(rawstor_mempool_allocated(p) == 2);

    rawstor_mempool_free(p, v2);
    assertTrue(rawstor_mempool_available(p) == 2);
    assertTrue(rawstor_mempool_allocated(p) == 1);

    rawstor_mempool_free(p, v1);
    assertTrue(rawstor_mempool_available(p) == 3);
    assertTrue(rawstor_mempool_allocated(p) == 0);

    rawstor_mempool_delete(p);

    return 0;
}

static int test_mempool_overflow() {
    RawstorMemPool* p = rawstor_mempool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int* v1 = rawstor_mempool_alloc(p);
    assertTrue(v1 != NULL);
    int* v2 = rawstor_mempool_alloc(p);
    assertTrue(v2 != NULL);
    int* v3 = rawstor_mempool_alloc(p);
    assertTrue(v3 != NULL);
    int* v4 = rawstor_mempool_alloc(p);
    assertTrue(v4 == NULL);
    assertTrue(errno == ENOBUFS);

    rawstor_mempool_delete(p);

    return 0;
}

int main() {
    int rval = 0;
    rval += test_mempool_alloc();
    rval += test_mempool_free();
    rval += test_mempool_create();
    rval += test_mempool_data();
    rval += test_mempool_order();
    rval += test_mempool_counters();
    rval += test_mempool_overflow();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
