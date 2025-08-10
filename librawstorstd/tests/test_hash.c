#include "rawstorstd/hash.h"

#include "unittest.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>


static int test_hash_scalar() {
    const char *buf = "hello world";
    uint64_t hash = rawstor_hash_scalar((void*)buf, strlen(buf));
    assertTrue(hash == 0xd447b1ea40e6988b);
    return 0;
}


static int test_hash_vector() {
    struct iovec iov[] = {
        (struct iovec) {
            .iov_base = "hello",
            .iov_len = strlen("hello"),
        },
        (struct iovec) {
            .iov_base = " ",
            .iov_len = strlen(" "),
        },
        (struct iovec) {
            .iov_base = "world",
            .iov_len = strlen("world"),
        }
    };
    uint64_t hash = rawstor_hash_vector(iov, 3);
    assertTrue(hash == 0xd447b1ea40e6988b);
    return 0;
}


int main() {
    int rval = 0;
    rval += test_hash_scalar();
    rval += test_hash_vector();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
