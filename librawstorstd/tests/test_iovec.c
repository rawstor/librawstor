#include "rawstorstd/iovec.h"

#include "unittest.h"

#include <sys/uio.h>

#include <stdlib.h>
#include <string.h>

static int test_discard_front_unaligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 12);

    assertTrue(niov_at == 2);
    assertTrue(strncmp(iov_at[0].iov_base, "34567890", 8) == 0);
    assertTrue(iov_at[0].iov_len == 8);
    assertTrue(size == 12);
    return 0;
}

static int test_discard_front_aligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 10);

    assertTrue(niov_at == 2);
    assertTrue(strncmp(iov_at[0].iov_base, "1234567890", 10) == 0);
    assertTrue(iov_at[0].iov_len == 10);
    assertTrue(size == 10);
    return 0;
}

static int test_discard_front_all() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 30);

    assertTrue(niov_at == 0);
    assertTrue(size == 30);
    return 0;
}

static int test_discard_front_overflow() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_front(&iov_at, &niov_at, 35);

    assertTrue(niov_at == 0);
    assertTrue(size == 30);
    return 0;
}

static int test_discard_back_unaligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 12);

    assertTrue(niov_at == 2);
    assertTrue(strncmp(iov_at[1].iov_base, "12345678", 8) == 0);
    assertTrue(iov_at[1].iov_len == 8);
    assertTrue(size == 12);
    return 0;
}

static int test_discard_back_aligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 10);

    assertTrue(niov_at == 2);
    assertTrue(strncmp(iov_at[1].iov_base, "1234567890", 10) == 0);
    assertTrue(iov_at[1].iov_len == 10);
    assertTrue(size == 10);
    return 0;
}

static int test_discard_back_all() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 30);

    assertTrue(niov_at == 0);
    assertTrue(size == 30);
    return 0;
}

static int test_discard_back_overflow() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    struct iovec* iov_at = v;
    unsigned int niov_at = 3;

    size_t size = rawstor_iovec_discard_back(&iov_at, &niov_at, 35);

    assertTrue(niov_at == 0);
    assertTrue(size == 30);
    return 0;
}

static int test_from_buf_unaligned() {
    struct iovec v[3];
    char data0[] = "          ";
    v[0] = (struct iovec){
        .iov_base = data0,
        .iov_len = sizeof(data0) - 1,
    };
    char data1[] = "          ";
    v[1] = (struct iovec){
        .iov_base = data1,
        .iov_len = sizeof(data1) - 1,
    };
    char data2[] = "          ";
    v[2] = (struct iovec){
        .iov_base = data2,
        .iov_len = sizeof(data2) - 1,
    };

    char buf[] = "123456789012";
    size_t size = rawstor_iovec_from_buf(v, 3, 0, buf, sizeof(buf) - 1);

    assertTrue(size == 12);
    assertTrue(strncmp(v[0].iov_base, "1234567890", v[0].iov_len) == 0);
    assertTrue(strncmp(v[1].iov_base, "12        ", v[1].iov_len) == 0);
    assertTrue(strncmp(v[2].iov_base, "          ", v[2].iov_len) == 0);

    return 0;
}

static int test_from_buf_aligned() {
    struct iovec v[3];
    char data0[] = "          ";
    v[0] = (struct iovec){
        .iov_base = data0,
        .iov_len = sizeof(data0) - 1,
    };
    char data1[] = "          ";
    v[1] = (struct iovec){
        .iov_base = data1,
        .iov_len = sizeof(data1) - 1,
    };
    char data2[] = "          ";
    v[2] = (struct iovec){
        .iov_base = data2,
        .iov_len = sizeof(data2) - 1,
    };

    char buf[] = "1234567890";
    size_t size = rawstor_iovec_from_buf(v, 3, 0, buf, sizeof(buf) - 1);

    assertTrue(size == 10);
    assertTrue(strncmp(v[0].iov_base, "1234567890", v[0].iov_len) == 0);
    assertTrue(strncmp(v[1].iov_base, "          ", v[1].iov_len) == 0);
    assertTrue(strncmp(v[2].iov_base, "          ", v[2].iov_len) == 0);

    return 0;
}

static int test_from_buf_all() {
    struct iovec v[3];
    char data0[] = "          ";
    v[0] = (struct iovec){
        .iov_base = data0,
        .iov_len = sizeof(data0) - 1,
    };
    char data1[] = "          ";
    v[1] = (struct iovec){
        .iov_base = data1,
        .iov_len = sizeof(data1) - 1,
    };
    char data2[] = "          ";
    v[2] = (struct iovec){
        .iov_base = data2,
        .iov_len = sizeof(data2) - 1,
    };

    char buf[] = "123456789012345678901234567890";
    size_t size = rawstor_iovec_from_buf(v, 3, 0, buf, sizeof(buf) - 1);

    assertTrue(size == 30);
    assertTrue(strncmp(v[0].iov_base, "1234567890", v[0].iov_len) == 0);
    assertTrue(strncmp(v[1].iov_base, "1234567890", v[1].iov_len) == 0);
    assertTrue(strncmp(v[2].iov_base, "1234567890", v[2].iov_len) == 0);

    return 0;
}

static int test_from_buf_overflow() {
    struct iovec v[3];
    char data0[] = "          ";
    v[0] = (struct iovec){
        .iov_base = data0,
        .iov_len = sizeof(data0) - 1,
    };
    char data1[] = "          ";
    v[1] = (struct iovec){
        .iov_base = data1,
        .iov_len = sizeof(data1) - 1,
    };
    char data2[] = "          ";
    v[2] = (struct iovec){
        .iov_base = data2,
        .iov_len = sizeof(data2) - 1,
    };

    char buf[] = "12345678901234567890123456789012345";
    size_t size = rawstor_iovec_from_buf(v, 3, 0, buf, sizeof(buf) - 1);

    assertTrue(size == 30);
    assertTrue(strncmp(v[0].iov_base, "1234567890", v[0].iov_len) == 0);
    assertTrue(strncmp(v[1].iov_base, "1234567890", v[1].iov_len) == 0);
    assertTrue(strncmp(v[2].iov_base, "1234567890", v[2].iov_len) == 0);

    return 0;
}

static int test_to_buf_unaligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    char buf[12];
    size_t size = rawstor_iovec_to_buf(v, 3, 0, buf, sizeof(buf));

    assertTrue(size == 12);
    assertTrue(strncmp(buf, "123456789012", size) == 0);

    size = rawstor_iovec_to_buf(v, 3, 3, buf, sizeof(buf));

    assertTrue(size == 12);
    assertTrue(strncmp(buf, "456789012345", size) == 0);
    return 0;
}

static int test_to_buf_aligned() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    char buf[10];
    size_t size = rawstor_iovec_to_buf(v, 3, 0, buf, sizeof(buf));

    assertTrue(size == 10);
    assertTrue(strncmp(buf, "1234567890", size) == 0);

    size = rawstor_iovec_to_buf(v, 3, 10, buf, sizeof(buf));

    assertTrue(size == 10);
    assertTrue(strncmp(buf, "1234567890", size) == 0);

    return 0;
}

static int test_to_buf_all() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    char buf[30];
    size_t size = rawstor_iovec_to_buf(v, 3, 0, buf, sizeof(buf));

    assertTrue(size == 30);
    assertTrue(strncmp(buf, "123456789012345678901234567890", size) == 0);

    size = rawstor_iovec_to_buf(v, 3, 3, buf, sizeof(buf) - 3);

    assertTrue(size == 27);
    assertTrue(strncmp(buf, "456789012345678901234567890", size) == 0);

    return 0;
}

static int test_to_buf_overflow() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    char buf[35];
    size_t size = rawstor_iovec_to_buf(v, 3, 0, buf, sizeof(buf));

    assertTrue(size == 30);
    assertTrue(strncmp(buf, "123456789012345678901234567890", size) == 0);

    size = rawstor_iovec_to_buf(v, 3, 3, buf, sizeof(buf));

    assertTrue(size == 27);
    assertTrue(strncmp(buf, "456789012345678901234567890", size) == 0);

    return 0;
}

static int test_size() {
    char data[] = "1234567890";
    struct iovec v[3];
    v[0] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[1] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };
    v[2] = (struct iovec){
        .iov_base = data,
        .iov_len = sizeof(data) - 1,
    };

    assertTrue(rawstor_iovec_size(v, 3) == 30);

    return 0;
}

int main() {
    int rval = 0;
    rval += test_discard_front_unaligned();
    rval += test_discard_front_aligned();
    rval += test_discard_front_all();
    rval += test_discard_front_overflow();
    rval += test_discard_back_unaligned();
    rval += test_discard_back_aligned();
    rval += test_discard_back_all();
    rval += test_discard_back_overflow();
    rval += test_from_buf_unaligned();
    rval += test_from_buf_aligned();
    rval += test_from_buf_all();
    rval += test_from_buf_overflow();
    rval += test_to_buf_unaligned();
    rval += test_to_buf_aligned();
    rval += test_to_buf_all();
    rval += test_to_buf_overflow();
    rval += test_size();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
