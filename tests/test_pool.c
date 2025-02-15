#include "pool.h"

#include "utils.h"

#include <errno.h>
#include <stdlib.h>


static int test_pool_alloc() {
    RawstorPool *p = rawstor_pool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int *v1 = rawstor_pool_alloc(p);
    *v1 = 1;

    int *v2 = rawstor_pool_alloc(p);
    *v2 = 2;

    int *v3 = rawstor_pool_alloc(p);
    *v3 = 3;

    rawstor_pool_free(p, v1);
    rawstor_pool_free(p, v2);
    rawstor_pool_free(p, v3);

    rawstor_pool_delete(p);

    return 0;
}


static int test_pool_free() {
    RawstorPool *p = rawstor_pool_create(3, sizeof(int));
    assertTrue(p != NULL);

    rawstor_pool_alloc(p);

    rawstor_pool_alloc(p);

    int *v3 = rawstor_pool_alloc(p);

    rawstor_pool_free(p, v3);

    int *v3a = rawstor_pool_alloc(p);
    assertTrue(v3a == v3);

    rawstor_pool_delete(p);

    return 0;
}


static int test_pool_size() {
    RawstorPool *p = rawstor_pool_create(3, sizeof(int));
    assertTrue(p != NULL);

    assertTrue(rawstor_pool_size(p) == sizeof(int));

    rawstor_pool_delete(p);

    return 0;
}


static int test_pool_data() {
    RawstorPool *p = rawstor_pool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int *v1 = rawstor_pool_alloc(p);
    *v1 = 1;

    int *v2 = rawstor_pool_alloc(p);
    *v2 = 2;

    int *v3 = rawstor_pool_alloc(p);
    *v3 = 3;

    int *data = rawstor_pool_data(p);
    assertTrue(data[0] == 1);
    assertTrue(data[1] == 2);
    assertTrue(data[2] == 3);

    rawstor_pool_delete(p);

    return 0;
}


static int test_pool_order() {
    RawstorPool *p = rawstor_pool_create(3, sizeof(int));
    assertTrue(p != NULL);

    int *v1 = rawstor_pool_alloc(p);
    int *v2 = rawstor_pool_alloc(p);
    int *v3 = rawstor_pool_alloc(p);

    rawstor_pool_free(p, v2);
    rawstor_pool_free(p, v3);
    rawstor_pool_free(p, v1);

    int *v1a = rawstor_pool_alloc(p);
    assertTrue(v1a == v1);

    int *v3a = rawstor_pool_alloc(p);
    assertTrue(v3a == v3);

    int *v2a = rawstor_pool_alloc(p);
    assertTrue(v2a == v2);

    rawstor_pool_delete(p);

    return 0;
}


static int test_pool_counters() {
    RawstorPool *p = rawstor_pool_create(3, sizeof(int));
    assertTrue(p != NULL);

    assertTrue(rawstor_pool_available(p) == 3);
    assertTrue(rawstor_pool_allocated(p) == 0);

    int *v1 = rawstor_pool_alloc(p);
    assertTrue(rawstor_pool_available(p) == 2);
    assertTrue(rawstor_pool_allocated(p) == 1);

    int *v2 = rawstor_pool_alloc(p);
    assertTrue(rawstor_pool_available(p) == 1);
    assertTrue(rawstor_pool_allocated(p) == 2);

    int *v3 = rawstor_pool_alloc(p);
    assertTrue(rawstor_pool_available(p) == 0);
    assertTrue(rawstor_pool_allocated(p) == 3);

    rawstor_pool_free(p, v3);
    assertTrue(rawstor_pool_available(p) == 1);
    assertTrue(rawstor_pool_allocated(p) == 2);

    rawstor_pool_free(p, v2);
    assertTrue(rawstor_pool_available(p) == 2);
    assertTrue(rawstor_pool_allocated(p) == 1);

    rawstor_pool_free(p, v1);
    assertTrue(rawstor_pool_available(p) == 3);
    assertTrue(rawstor_pool_allocated(p) == 0);

    rawstor_pool_delete(p);

    return 0;
}


int main() {
    int rval = 0;
    rval += test_pool_alloc();
    rval += test_pool_free();
    rval += test_pool_size();
    rval += test_pool_data();
    rval += test_pool_order();
    rval += test_pool_counters();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
