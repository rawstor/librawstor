#include "testio.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


typedef struct {
    unsigned int index;
    off_t offset;

    struct iovec src_iov;
    struct iovec dst_iov;

    unsigned int *counter;
    unsigned int iteration;
    unsigned int niterations;
} Worker;


static Worker* worker_create(
    unsigned int index, size_t block_size,
    unsigned int *counter, unsigned int niterations)
{
    Worker *worker = malloc(sizeof(Worker));
    if (worker == NULL) {
        goto err_worker;
    }

    *worker = (Worker) {
        .index = index,
        .offset = block_size * index,
        .src_iov.iov_len = block_size,
        .dst_iov.iov_len = block_size,
        .counter = counter,
        .iteration = 0,
        .niterations = niterations,
    };

    worker->src_iov.iov_base = malloc(block_size);
    if (worker->src_iov.iov_base == NULL) {
        goto err_src_iov;
    }

    worker->dst_iov.iov_base = malloc(block_size);
    if (worker->dst_iov.iov_base == NULL) {
        goto err_dst_iov;
    }

    return worker;

err_dst_iov:
    free(worker->src_iov.iov_base);
err_src_iov:
    free(worker);
err_worker:
    return NULL;
}


static void worker_delete(Worker *worker) {
    free(worker->dst_iov.iov_base);
    free(worker->src_iov.iov_base);
    free(worker);
}


static void print_buf(const char *buf, size_t size) {
    printf("'");
    for (size_t i = 0; i < size; ++i) {
        putc(buf[i], stdout);
    }
    printf("'\n");
}


static void fill(
    char *buffer, size_t size, unsigned int index, unsigned int iteration)
{
    while (1) {
        int res = snprintf(
            buffer, size, "<worker %u iteration %u> ",
            index, iteration + 1);
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
    Worker *worker = (Worker*)data;

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
            worker->index, __FUNCTION__,
            worker->iteration + 1, worker->niterations);
    }

    --(*worker->counter);
    ++worker->iteration;

    if (worker->iteration >= worker->niterations) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    fill(
        worker->src_iov.iov_base, worker->src_iov.iov_len,
        worker->index, worker->iteration);

    return rawstor_object_pwrite(
        object,
        worker->src_iov.iov_base, worker->src_iov.iov_len, worker->offset,
        src_data_sent, worker);
}


static int dstv_data_received(
    RawstorObject *object, size_t size, size_t result, int error, void *data)
{
    Worker *worker = (Worker*)data;

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
            worker->index, __FUNCTION__,
            worker->iteration + 1, worker->niterations);
    }

    --(*worker->counter);
    ++worker->iteration;

    if (worker->iteration >= worker->niterations) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    fill(
        worker->src_iov.iov_base, worker->src_iov.iov_len,
        worker->index, worker->iteration);

    return rawstor_object_pwritev(
        object,
        &worker->src_iov, 1, worker->src_iov.iov_len, worker->offset,
        srcv_data_sent, worker);
}


static int src_data_sent(
    RawstorObject *object, size_t size, size_t result, int error, void *data)
{
    Worker *worker = (Worker*)data;

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
    Worker *worker = (Worker*)data;

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
    const struct RawstorOpts *opts,
    const struct RawstorSocketAddress *default_ost,
    const struct RawstorUUID *object_id,
    size_t block_size, unsigned int count, unsigned int io_depth,
    int vector_mode)
{
    if (rawstor_initialize(opts, default_ost)) {
        perror("rawstor_initialize() failed");
        goto err_initialize;
    }

    RawstorObject *object;
    if (rawstor_object_open(object_id, &object)) {
        perror("rawstor_object_open() failed");
        goto err_open;
    }

    unsigned int counter = count * io_depth;
    Worker **workers = calloc(io_depth, sizeof(Worker*));
    if (workers == NULL) {
        goto err_workers;
    }
    for (unsigned int i = 0; i < io_depth; ++i) {
        workers[i] = worker_create(i, block_size, &counter, count);
        if (workers[i] == NULL) {
            perror("worker_create() failed");
            goto err_worker_create;
        }
    }

    if (!vector_mode) {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(
                workers[i]->src_iov.iov_base, workers[i]->src_iov.iov_len,
                i, 0);
            if (rawstor_object_pwrite(
                object,
                workers[i]->src_iov.iov_base, workers[i]->src_iov.iov_len,
                workers[i]->offset,
                src_data_sent, workers[i]))
            {
                perror("rawstor_object_pwrite() failed");
                goto err_pwrite;
            }
        }
    } else {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(
                workers[i]->src_iov.iov_base, workers[i]->src_iov.iov_len,
                i, 0);
            if (rawstor_object_pwritev(
                object,
                &workers[i]->src_iov, 1, workers[i]->src_iov.iov_len,
                workers[i]->offset,
                srcv_data_sent, workers[i]))
            {
                perror("rawstor_object_pwritev() failed");
                goto err_pwrite;
            }
        }
    }

    while (counter > 0) {
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            assert(errno != 0);
            perror("rawstor_wait_event() failed");
            goto err_wait;
        }

        int rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);

        if (rval) {
            if (errno) {
                perror("rawstor_dispatch_event() failed");
            } else {
                printf("rawstor_dispatch_event(): returns %d\n", rval);
            }
            goto err_dispatch;
        }
    }

    if (rawstor_object_close(object)) {
        perror("rawstor_object_close() failed");
    }

    for (unsigned int i = 0; i < io_depth; ++i) {
        worker_delete(workers[i]);
    }
    free(workers);

    rawstor_terminate();

    printf("Success!\n");

    return EXIT_SUCCESS;

err_dispatch:
err_wait:
err_pwrite:
err_worker_create:
    for (unsigned int i = 0; i < io_depth; ++i) {
        if (workers[i] != NULL) {
            worker_delete(workers[i]);
        }
    }
    free(workers);
err_workers:
    if (rawstor_object_close(object)) {
        perror("rawstor_object_close() failed");
    }
err_open:
    rawstor_terminate();
err_initialize:
    return EXIT_FAILURE;
}
