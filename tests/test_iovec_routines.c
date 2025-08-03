#include "iovec_routines.h"

#include "utils.h"

#include <sys/uio.h>

#include <stdlib.h>
#include <string.h>


static int test_shift_unalligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec *iov_at = v;
    unsigned int niov_at = 3;

    size_t shift = rawstor_iovec_shift(&iov_at, &niov_at, 12);

    assertTrue(niov_at == 2);
    assertTrue(strcmp(iov_at[0].iov_base, "34567890") == 0);
    assertTrue(shift == 0);
    return 0;
}


static int test_shift_alligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec *iov_at = v;
    unsigned int niov_at = 3;

    size_t shift = rawstor_iovec_shift(&iov_at, &niov_at, 10);

    assertTrue(niov_at == 2);
    assertTrue(strcmp(iov_at[0].iov_base, "1234567890") == 0);
    assertTrue(shift == 0);
    return 0;
}


static int test_shift_all() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec *iov_at = v;
    unsigned int niov_at = 3;

    size_t shift = rawstor_iovec_shift(&iov_at, &niov_at, 30);

    assertTrue(niov_at == 0);
    assertTrue(shift == 0);
    return 0;
}


static int test_shift_overflow() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec) {
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec *iov_at = v;
    unsigned int niov_at = 3;

    size_t shift = rawstor_iovec_shift(&iov_at, &niov_at, 35);

    assertTrue(niov_at == 0);
    assertTrue(shift == 5);
    return 0;
}


int main() {
    int rval = 0;
    rval += test_shift_unalligned();
    rval += test_shift_alligned();
    rval += test_shift_all();
    rval += test_shift_overflow();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
