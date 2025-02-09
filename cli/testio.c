#include "testio.h"

#include "gcc.h"

#include <rawstor.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct Worker {
    unsigned int index;
    struct iovec src_iov;
    struct iovec dst_iov;
    unsigned int count;
};


static void print_buf(const char *buf, size_t size) {
    printf("'");
    for (size_t i = 0; i < size; ++i) {
        putc(buf[i], stdout);
    }
    printf("'\n");
}


static void fill(char *buffer, size_t size) {
    for (unsigned int i = 0; i < size; ++i) {
        buffer[i] = 'a' + rand() % ('z' - 'a' + 1);
    }
}


static int src_data_sent(
    RawstorObject *object, off_t offset,
    void RAWSTOR_CLI_UNUSED *buf, size_t size,
    ssize_t res, void *data);


static int srcv_data_sent(
    RawstorObject *object, off_t offset,
    struct iovec RAWSTOR_CLI_UNUSED *iov, unsigned int RAWSTOR_CLI_UNUSED niov,
    size_t size,
    ssize_t res, void *data);


static int dst_data_received(
    RawstorObject *object, off_t offset,
    void RAWSTOR_CLI_UNUSED *buf, size_t size,
    ssize_t res, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): res = %zd\n", worker->index, __FUNCTION__, res);

    if (res < 0) {
        errno = -res;
        return res;
    }

    if (res == 0) {
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if ((size_t)res != size) {
        printf(
            "(%u) %s(): Partial read: %zu != %zu\n",
            worker->index, __FUNCTION__, (size_t)res, size);
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
    }

    if (worker->count <= 1) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    --worker->count;
    fill(worker->src_iov.iov_base, worker->src_iov.iov_len);

    return rawstor_object_write(
        object, offset,
        worker->src_iov.iov_base, worker->src_iov.iov_len,
        src_data_sent, worker);
}


static int dstv_data_received(
    RawstorObject *object, off_t offset,
    struct iovec RAWSTOR_CLI_UNUSED *iov, unsigned int RAWSTOR_CLI_UNUSED niov,
    size_t size,
    ssize_t res, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): res = %zd\n", worker->index, __FUNCTION__, res);

    if (res < 0) {
        errno = -res;
        return res;
    }

    if (res == 0) {
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if ((size_t)res != size) {
        printf(
            "(%u) %s(): Partial read: %zu != %zu\n",
            worker->index, __FUNCTION__, (size_t)res, size);
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
    }

    if (worker->count <= 1) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    --worker->count;
    fill(worker->src_iov.iov_base, worker->src_iov.iov_len);

    return rawstor_object_writev(
        object, offset,
        &worker->src_iov, 1, size,
        srcv_data_sent, worker);
}


static int src_data_sent(
    RawstorObject *object, off_t offset,
    void RAWSTOR_CLI_UNUSED *buf, size_t size,
    ssize_t res, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): res = %zd\n", worker->index, __FUNCTION__, res);

    if (res < 0) {
        errno = -res;
        return res;
    }

    if (res == 0) {
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if ((size_t)res != size) {
        printf(
            "(%u) %s(): Partial write: %zu != %zu\n",
            worker->index, __FUNCTION__, (size_t)res, size);
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (rawstor_object_read(
        object, offset,
        worker->dst_iov.iov_base, worker->dst_iov.iov_len,
        dst_data_received, worker))
    {
        perror("rawstor_object_read() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


static int srcv_data_sent(
    RawstorObject *object, off_t offset,
    struct iovec RAWSTOR_CLI_UNUSED *iov, unsigned int RAWSTOR_CLI_UNUSED niov,
    size_t size,
    ssize_t res, void *data)
{
    struct Worker *worker = (struct Worker*)data;

    printf("(%u) %s(): res = %zd\n", worker->index, __FUNCTION__, res);

    if (res < 0) {
        errno = -res;
        return res;
    }

    if (res == 0) {
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if ((size_t)res != size) {
        printf(
            "(%u) %s(): Partial write: %zu != %zu\n",
            worker->index, __FUNCTION__, (size_t)res, size);
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    if (rawstor_object_readv(
        object, offset,
        &worker->dst_iov, 1, size,
        dstv_data_received, worker))
    {
        perror("rawstor_object_readv() failed");
        /**
         * TODO: Find errno here.
         */
        return -1;
    }

    return 0;
}


int rawstor_cli_testio(
    int object_id,
    size_t block_size, unsigned int count, unsigned int io_depth,
    int vector_mode)
{
    if (rawstor_initialize()) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    RawstorObject *object;
    if (rawstor_object_open(object_id, &object)) {
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
            .src_iov.iov_base = malloc(block_size),
            .src_iov.iov_len = block_size,
            .dst_iov.iov_base = malloc(block_size),
            .dst_iov.iov_len = block_size,
            .count = count,
        };
    }

    if (!vector_mode) {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(workers[i].src_iov.iov_base, workers[i].src_iov.iov_len);
            if (rawstor_object_write(
                object, block_size * (i + 1),
                workers[i].src_iov.iov_base, workers[i].src_iov.iov_len,
                src_data_sent, &workers[i]))
            {
                perror("rawstor_object_write() failed");
                return EXIT_FAILURE;
            }
        }
    } else {
        for (unsigned int i = 0; i < io_depth; ++i) {
            if (rawstor_object_writev(
                object, 1 + block_size * i,
                &workers[i].src_iov, 1, block_size,
                srcv_data_sent, &workers[i]))
            {
                perror("rawstor_object_writev() failed");
                return EXIT_FAILURE;
            }
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
