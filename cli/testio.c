#include "testio.h"

#include "gcc.h"

#include <rawstor.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>


int read_cb(
    RawstorObject RAWSTOR_CLI_UNUSED *object, off_t RAWSTOR_CLI_UNUSED offset,
    void *buf, size_t RAWSTOR_CLI_UNUSED size,
    ssize_t res, void RAWSTOR_CLI_UNUSED *data)
{
    printf("read_cb(): res = %zd\n", res);

    if (res < 0) {
        printf("read_cb(): res < 0\n");
        errno = -res;
        return res;
    }

    if (res == 0) {
        printf("read_cb(): res == 0\n");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    printf("buf: '");
    for (ssize_t i = 0; i < res; ++i) {
        putc(((char*)buf)[i], stdout);
    }
    printf("'\n");

    return 0;
}


int readv_cb(
    RawstorObject RAWSTOR_CLI_UNUSED *object, off_t RAWSTOR_CLI_UNUSED offset,
    struct iovec *iov, unsigned int RAWSTOR_CLI_UNUSED niov,
    size_t RAWSTOR_CLI_UNUSED size,
    ssize_t res, void RAWSTOR_CLI_UNUSED *data)
{
    printf("readv_cb(): res = %zd\n", res);

    if (res < 0) {
        printf("readv_cb(): res < 0\n");
        errno = -res;
        return res;
    }

    if (res == 0) {
        printf("readv_cb(): res == 0\n");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    printf("buf: '");
    for (ssize_t i = 0; i < res; ++i) {
        putc(((char*)iov[0].iov_base)[i], stdout);
    }
    printf("'\n");

    return 0;
}


int write_cb(
    RawstorObject *object, off_t offset,
    void RAWSTOR_CLI_UNUSED *buf, size_t size,
    ssize_t res, void *data)
{
    printf("write_cb(): res = %zd\n", res);

    if (res < 0) {
        printf("write_cb(): res < 0\n");
        errno = -res;
        return res;
    }

    if (res == 0) {
        printf("write_cb(): res == 0\n");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (rawstor_object_read(
        object, offset,
        data, size,
        read_cb, NULL))
    {
        perror("rawstor_object_read() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


int writev_cb(
    RawstorObject *object, off_t offset,
    struct iovec RAWSTOR_CLI_UNUSED *iov, unsigned int RAWSTOR_CLI_UNUSED niov,
    size_t size,
    ssize_t res, void *data)
{
    printf("writev_cb(): res = %zd\n", res);

    if (res < 0) {
        printf("writev_cb(): res < 0\n");
        errno = -res;
        return res;
    }

    if (res == 0) {
        printf("writev_cb(): res == 0\n");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (rawstor_object_readv(
        object, offset,
        (struct iovec*)data, 1, size,
        readv_cb, NULL))
    {
        perror("rawstor_object_readv() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


int rawstor_cli_testio(int object_id, int vector_mode) {
    if (rawstor_initialize()) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    RawstorObject *object;
    if (rawstor_object_open(object_id, &object)) {
        perror("rawstor_object_open() failed");
        return EXIT_FAILURE;
    }

    char write_buf[] = "hello world";
    struct iovec write_iov = {
        .iov_base = write_buf,
        .iov_len = sizeof(write_buf),
    };

    char read_buf[256];
    struct iovec read_iov = {
        .iov_base = read_buf,
        .iov_len = sizeof(read_buf),
    };

    if (!vector_mode) {
        if (rawstor_object_write(
            object, 100,
            write_buf, sizeof(write_buf),
            write_cb, read_buf))
        {
            perror("rawstor_object_write() failed");
            return EXIT_FAILURE;
        }
    } else {
        if (rawstor_object_writev(
            object, 100,
            &write_iov, 1, sizeof(write_buf),
            writev_cb, &read_iov))
        {
            perror("rawstor_object_writev() failed");
            return EXIT_FAILURE;
        }
    }

    while (1) {
        RawstorAIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            printf("rawstor_wait_event(): returns NULL\n");
            break;
        }

        int rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);

        if (rval) {
            printf("rawstor_dispatch_event(): returns %d\n", rval);
            break;
        }
    }

    if (rawstor_object_close(object)) {
        perror("rawstor_object_close() failed");
        return EXIT_FAILURE;
    }
    rawstor_terminate();

    return EXIT_SUCCESS;
}
