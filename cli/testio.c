#include "testio.h"

#include "gcc.h"

#include <rawstor.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct Worker {
    unsigned int index;
    off_t offset;

    struct iovec src_iov;
    struct iovec dst_iov;

    unsigned int current;
    unsigned int total;
};


static void print_buf(const char *buf, size_t size) {
    printf("'");
    for (size_t i = 0; i < size; ++i) {
        putc(buf[i], stdout);
    }
    printf("'\n");
}


/*
static void fill(char *buffer, size_t size) {
    for (unsigned int i = 0; i < size; ++i) {
        buffer[i] = 'a' + rand() % ('z' - 'a' + 1);
    }
}
*/


static void fill(
    char *buffer, size_t size, unsigned int index, unsigned int current)
{
    while (1) {
        int res = snprintf(
            buffer, size, "<worker %u iteration %u> ",
            index, current + 1);
        if (res < 0) {
            break;
        }
        buffer += res;
        if (size < (size_t)res) {
            break;
        }
        size -= res;
        if (size == 0) {
            break;
        }
    }
}


static int src_data_sent(
    RawstorObject *object, size_t size, size_t result, int error, void *data);


static int srcv_data_sent(
    RawstorObject *object, size_t size, size_t res, int error, void *data);


static int dst_data_received(
    RawstorObject *object, size_t size, size_t result, int error, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        errno = error;
        return -errno;
    }

    if (result != size) {
        printf(
            "(%u) %s(): Partial read: %zu != %zu\n",
            worker->index, __FUNCTION__, result, size);
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (strncmp(worker->src_iov.iov_base, worker->dst_iov.iov_base, size)) {
        printf("(%u) %s(): src != dst\n", worker->index, __FUNCTION__);
        printf("(%u) %s(): src = ", worker->index, __FUNCTION__);
        print_buf(worker->src_iov.iov_base, worker->src_iov.iov_len);
        printf("(%u) %s(): dst = ", worker->index, __FUNCTION__);
        print_buf(worker->dst_iov.iov_base, worker->dst_iov.iov_len);
        /**
         * TODO: Find errno here.
         */
        return -1;
    } else {
        printf(
            "(%u) %s(): src == dst on %u of %u\n",
            worker->index, __FUNCTION__, worker->current + 1, worker->total);
    }

    if (worker->current >= worker->total - 1) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    ++worker->current;
    fill(
        worker->src_iov.iov_base, worker->src_iov.iov_len,
        worker->index, worker->current);

    return rawstor_object_pwrite(
        object,
        worker->src_iov.iov_base, worker->src_iov.iov_len, worker->offset,
        src_data_sent, worker);
}


static int dstv_data_received(
    RawstorObject *object, size_t size, size_t result, int error, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        errno = error;
        return -errno;
    }

    if (result != size) {
        printf(
            "(%u) %s(): Partial read: %zu != %zu\n",
            worker->index, __FUNCTION__, result, size);
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (strncmp(worker->src_iov.iov_base, worker->dst_iov.iov_base, size)) {
        printf("(%u) %s(): src != dst\n", worker->index, __FUNCTION__);
        printf("(%u) %s(): src = ", worker->index, __FUNCTION__);
        print_buf(worker->src_iov.iov_base, worker->src_iov.iov_len);
        printf("(%u) %s(): dst = ", worker->index, __FUNCTION__);
        print_buf(worker->dst_iov.iov_base, worker->dst_iov.iov_len);
        /**
         * TODO: Find errno here.
         */
        return -1;
    } else {
        printf(
            "(%u) %s(): src == dst on %u of %u\n",
            worker->index, __FUNCTION__, worker->current + 1, worker->total);
    }

    if (worker->current >= worker->total - 1) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    ++worker->current;
    fill(
        worker->src_iov.iov_base, worker->src_iov.iov_len,
        worker->index, worker->current);

    return rawstor_object_pwritev(
        object,
        &worker->src_iov, 1, worker->src_iov.iov_len, worker->offset,
        srcv_data_sent, worker);
}


static int src_data_sent(
    RawstorObject *object, size_t size, size_t result, int error, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        errno = error;
        return -errno;
    }

    if (result != size) {
        printf(
            "(%u) %s(): Partial write: %zu != %zu\n",
            worker->index, __FUNCTION__, result, size);
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (rawstor_object_pread(
        object,
        worker->dst_iov.iov_base, worker->dst_iov.iov_len, worker->offset,
        dst_data_received, worker))
    {
        perror("rawstor_object_pread() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


static int srcv_data_sent(
    RawstorObject *object, size_t size, size_t result, int error, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        errno = error;
        return -errno;
    }

    if (result != size) {
        printf(
            "(%u) %s(): Partial write: %zu != %zu\n",
            worker->index, __FUNCTION__, result, size);
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (rawstor_object_preadv(
        object,
        &worker->dst_iov, 1, worker->dst_iov.iov_len, worker->offset,
        dstv_data_received, worker))
    {
        perror("rawstor_object_preadv() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


int rawstor_cli_testio(
    const RawstorConfig *config,
    const RawstorUUID *object_id,
    size_t block_size, unsigned int count, unsigned int io_depth,
    int vector_mode)
{
    if (rawstor_initialize(config)) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    RawstorObject *object;
    if (rawstor_object_open(NULL, object_id, &object)) {
        perror("rawstor_object_open() failed");
        return EXIT_FAILURE;
    }

    /**
     * TODO: free workers
     */
    struct Worker *workers = calloc(io_depth, sizeof(struct Worker));
    for (unsigned int i = 0; i < io_depth; ++i) {
        workers[i] = (struct Worker) {
            .index = i,
            .offset = block_size * i,
            .src_iov.iov_base = malloc(block_size),
            .src_iov.iov_len = block_size,
            .dst_iov.iov_base = malloc(block_size),
            .dst_iov.iov_len = block_size,
            .current = 0,
            .total = count,
        };
    }

    if (!vector_mode) {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(
                workers[i].src_iov.iov_base, workers[i].src_iov.iov_len,
                i, 0);
            if (rawstor_object_pwrite(
                object,
                workers[i].src_iov.iov_base, workers[i].src_iov.iov_len,
                workers[i].offset,
                src_data_sent, &workers[i]))
            {
                perror("rawstor_object_pwrite() failed");
                return EXIT_FAILURE;
            }
        }
    } else {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(
                workers[i].src_iov.iov_base, workers[i].src_iov.iov_len,
                i, 0);
            if (rawstor_object_pwritev(
                object,
                &workers[i].src_iov, 1, workers[i].src_iov.iov_len,
                workers[i].offset,
                srcv_data_sent, &workers[i]))
            {
                perror("rawstor_object_pwritev() failed");
                return EXIT_FAILURE;
            }
        }
    }

    int ret = EXIT_SUCCESS;
    while (1) {
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            if (errno) {
                perror("rawstor_wait_event() failed");
                ret = EXIT_FAILURE;
            } else {
                printf("rawstor_wait_event(): returns NULL\n");
            }
            break;
        }

        int rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);

        if (rval) {
            if (errno) {
                perror("rawstor_dispatch_event() failed");
            } else {
                printf("rawstor_dispatch_event(): returns %d\n", rval);
            }
            ret = EXIT_FAILURE;
            break;
        }
    }

    if (rawstor_object_close(object)) {
        perror("rawstor_object_close() failed");
        ret = EXIT_FAILURE;
    }

    rawstor_terminate();

    return ret;
}
