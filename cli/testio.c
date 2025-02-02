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

    if (rawstor_object_read(object, offset, data, size, read_cb, NULL)) {
        perror("rawstor_object_read() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


int rawstor_cli_testio(int object_id) {
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

    char read_buf[256];
    if (rawstor_object_write(
        object, 100,
        write_buf, sizeof(write_buf),
        write_cb, read_buf))
    {
        perror("rawstor_object_write() failed");
        return EXIT_FAILURE;
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
