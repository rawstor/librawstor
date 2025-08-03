#include "ringbuf.h"

#include "utils.h"

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>


static int test_ringbuf_empty() {
    RawstorRingBuf *buf = rawstor_ringbuf_create(3, sizeof(int));

    assertTrue(rawstor_ringbuf_pop(buf) == -ENOBUFS);
    assertTrue(errno == ENOBUFS);

    assertTrue(rawstor_ringbuf_empty(buf) != 0);
    assertTrue(rawstor_ringbuf_size(buf) == 0);
    assertTrue(rawstor_ringbuf_iter(buf) == NULL);

    rawstor_ringbuf_delete(buf);
    return 0;
}


static int test_ringbuf_invalid() {
    RawstorRingBuf *buf = rawstor_ringbuf_create(0, sizeof(int));

    assertTrue(buf == NULL);
    assertTrue(errno == EINVAL);

    return 0;
}


static int test_ringbuf_basics() {
    RawstorRingBuf *buf = rawstor_ringbuf_create(3, sizeof(int));

    assertTrue(rawstor_ringbuf_empty(buf) != 0);

    *(int*)rawstor_ringbuf_head(buf) = 1;
    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_empty(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 2;
    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_empty(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 3;
    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_empty(buf) == 0);

    assertTrue(rawstor_ringbuf_push(buf) == -ENOBUFS);
    assertTrue(errno == ENOBUFS);

    assertTrue(*(int*)rawstor_ringbuf_tail(buf) == 1);
    assertTrue(rawstor_ringbuf_pop(buf) == 0);
    assertTrue(rawstor_ringbuf_empty(buf) == 0);

    assertTrue(*(int*)rawstor_ringbuf_tail(buf) == 2);
    assertTrue(rawstor_ringbuf_pop(buf) == 0);
    assertTrue(rawstor_ringbuf_empty(buf) == 0);

    assertTrue(*(int*)rawstor_ringbuf_tail(buf) == 3);
    assertTrue(rawstor_ringbuf_pop(buf) == 0);
    assertTrue(rawstor_ringbuf_empty(buf) != 0);

    assertTrue(rawstor_ringbuf_pop(buf) == -ENOBUFS);
    assertTrue(errno == ENOBUFS);

    rawstor_ringbuf_delete(buf);
    return 0;
}


static int test_ringbuf_overlap() {
    RawstorRingBuf *buf = rawstor_ringbuf_create(4, sizeof(int));

    assertTrue(rawstor_ringbuf_size(buf) == 0);

    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 1);

    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 2);

    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 3);

    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 4);

    assertTrue(rawstor_ringbuf_push(buf) != 0);
    assertTrue(rawstor_ringbuf_size(buf) == 4);

    assertTrue(rawstor_ringbuf_pop(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 3);
    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 4);

    assertTrue(rawstor_ringbuf_pop(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 3);
    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_size(buf) == 4);

    rawstor_ringbuf_delete(buf);
    return 0;
}


static int test_ringbuf_iter() {
    RawstorRingBuf *buf = rawstor_ringbuf_create(3, sizeof(int));

    *(int*)rawstor_ringbuf_head(buf) = 1;
    assertTrue(rawstor_ringbuf_push(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 2;
    assertTrue(rawstor_ringbuf_push(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 3;
    assertTrue(rawstor_ringbuf_push(buf) == 0);

    void *it = rawstor_ringbuf_iter(buf);
    assertTrue(it != NULL);
    assertTrue(*(int*)it == 1);

    it = rawstor_ringbuf_next(buf, it);
    assertTrue(it != NULL);
    assertTrue(*(int*)it == 2);

    it = rawstor_ringbuf_next(buf, it);
    assertTrue(it != NULL);
    assertTrue(*(int*)it == 3);

    it = rawstor_ringbuf_next(buf, it);
    assertTrue(it == NULL);

    rawstor_ringbuf_delete(buf);
    return 0;
}


static int test_ringbuf_iter_shifted() {
    RawstorRingBuf *buf = rawstor_ringbuf_create(3, sizeof(int));

    assertTrue(rawstor_ringbuf_push(buf) == 0);
    assertTrue(rawstor_ringbuf_pop(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 1;
    assertTrue(rawstor_ringbuf_push(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 2;
    assertTrue(rawstor_ringbuf_push(buf) == 0);

    *(int*)rawstor_ringbuf_head(buf) = 3;
    assertTrue(rawstor_ringbuf_push(buf) == 0);

    void *it = rawstor_ringbuf_iter(buf);
    assertTrue(it != NULL);
    assertTrue(*(int*)it == 1);

    it = rawstor_ringbuf_next(buf, it);
    assertTrue(it != NULL);
    assertTrue(*(int*)it == 2);

    it = rawstor_ringbuf_next(buf, it);
    assertTrue(it != NULL);
    assertTrue(*(int*)it == 3);

    it = rawstor_ringbuf_next(buf, it);
    assertTrue(it == NULL);

    rawstor_ringbuf_delete(buf);
    return 0;
}


int main() {
    int rval = 0;
    rval += test_ringbuf_empty();
    rval += test_ringbuf_invalid();
    rval += test_ringbuf_basics();
    rval += test_ringbuf_overlap();
    rval += test_ringbuf_iter();
    rval += test_ringbuf_iter_shifted();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
