#include "testio.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    RawstorObject* object;
    unsigned int index;
    off_t offset;

    struct iovec src_iov;
    struct iovec dst_iov;

    unsigned int* counter;
    unsigned int iteration;
    unsigned int niterations;
    int sync;
} Worker;

static Worker* worker_create(
    RawstorObject* object, unsigned int index, uint64_t block_size,
    unsigned int* counter, unsigned int niterations, int sync
) {
    Worker* worker = malloc(sizeof(Worker));
    if (worker == NULL) {
        goto err_worker;
    }

    *worker = (Worker){
        .object = object,
        .index = index,
        .offset = block_size * index,
        .src_iov.iov_len = block_size,
        .dst_iov.iov_len = block_size,
        .counter = counter,
        .iteration = 0,
        .niterations = niterations,
        .sync = sync,
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

static void worker_delete(Worker* worker) {
    free(worker->dst_iov.iov_base);
    free(worker->src_iov.iov_base);
    free(worker);
}

static void print_buf(const char* buf, size_t size) {
    printf("'");
    for (size_t i = 0; i < size; ++i) {
        putc(buf[i], stdout);
    }
    printf("'\n");
}

static void
fill(char* buffer, size_t size, unsigned int index, unsigned int iteration) {
    while (1) {
        int res = snprintf(
            buffer, size, "<worker %u iteration %u> ", index, iteration + 1
        );
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

static int src_data_sent(size_t result, int error, void* data);

static int srcv_data_sent(size_t result, int error, void* data);

static int dst_data_received(size_t result, int error, void* data) {
    Worker* worker = (Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        return -error;
    }

    if (result != worker->dst_iov.iov_len) {
        printf(
            "(%u) %s(): Partial read: %zu != %zu\n", worker->index,
            __FUNCTION__, result, worker->dst_iov.iov_len
        );
        return -EIO;
    }

    if (strncmp(
            worker->src_iov.iov_base, worker->dst_iov.iov_base,
            worker->dst_iov.iov_len
        )) {
        printf("(%u) %s(): src != dst\n", worker->index, __FUNCTION__);
        printf("(%u) %s(): src = ", worker->index, __FUNCTION__);
        print_buf(worker->src_iov.iov_base, worker->src_iov.iov_len);
        printf("(%u) %s(): dst = ", worker->index, __FUNCTION__);
        print_buf(worker->dst_iov.iov_base, worker->dst_iov.iov_len);
        return -EIO;
    } else {
        printf(
            "(%u) %s(): src == dst on %u of %u\n", worker->index, __FUNCTION__,
            worker->iteration + 1, worker->niterations
        );
    }

    --(*worker->counter);
    ++worker->iteration;

    if (worker->iteration >= worker->niterations) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    fill(
        worker->src_iov.iov_base, worker->src_iov.iov_len, worker->index,
        worker->iteration
    );

    return rawstor_object_pwrite(
        worker->object, worker->src_iov.iov_base, worker->src_iov.iov_len,
        worker->offset, worker->sync, src_data_sent, worker
    );
}

static int dstv_data_received(size_t result, int error, void* data) {
    Worker* worker = (Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        return -error;
    }

    if (result != worker->dst_iov.iov_len) {
        printf(
            "(%u) %s(): Partial read: %zu != %zu\n", worker->index,
            __FUNCTION__, result, worker->dst_iov.iov_len
        );
        return -EIO;
    }

    if (strncmp(
            worker->src_iov.iov_base, worker->dst_iov.iov_base,
            worker->dst_iov.iov_len
        )) {
        printf("(%u) %s(): src != dst\n", worker->index, __FUNCTION__);
        printf("(%u) %s(): src = ", worker->index, __FUNCTION__);
        print_buf(worker->src_iov.iov_base, worker->src_iov.iov_len);
        printf("(%u) %s(): dst = ", worker->index, __FUNCTION__);
        print_buf(worker->dst_iov.iov_base, worker->dst_iov.iov_len);
        return -EIO;
    } else {
        printf(
            "(%u) %s(): src == dst on %u of %u\n", worker->index, __FUNCTION__,
            worker->iteration + 1, worker->niterations
        );
    }

    --(*worker->counter);
    ++worker->iteration;

    if (worker->iteration >= worker->niterations) {
        printf("(%u) %s(): Worker done\n", worker->index, __FUNCTION__);
        return 0;
    }

    fill(
        worker->src_iov.iov_base, worker->src_iov.iov_len, worker->index,
        worker->iteration
    );

    return rawstor_object_pwritev(
        worker->object, &worker->src_iov, 1, worker->src_iov.iov_len,
        worker->offset, worker->sync, srcv_data_sent, worker
    );
}

static int src_data_sent(size_t result, int error, void* data) {
    Worker* worker = (Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        return -error;
    }

    if (result != worker->src_iov.iov_len) {
        printf(
            "(%u) %s(): Partial write: %zu != %zu\n", worker->index,
            __FUNCTION__, result, worker->src_iov.iov_len
        );
        return -EIO;
    }

    return rawstor_object_pread(
        worker->object, worker->dst_iov.iov_base, worker->dst_iov.iov_len,
        worker->offset, dst_data_received, worker
    );
}

static int srcv_data_sent(size_t result, int error, void* data) {
    Worker* worker = (Worker*)data;

    printf("(%u) %s(): result = %zd\n", worker->index, __FUNCTION__, result);

    if (error != 0) {
        return -error;
    }

    if (result != worker->src_iov.iov_len) {
        printf(
            "(%u) %s(): Partial write: %zu != %zu\n", worker->index,
            __FUNCTION__, result, worker->src_iov.iov_len
        );
        return -EIO;
    }

    return rawstor_object_preadv(
        worker->object, &worker->dst_iov, 1, worker->dst_iov.iov_len,
        worker->offset, dstv_data_received, worker
    );
}

/* Synchronous open()/close() shims around the now-asynchronous
 * rawstor_target_open()/rawstor_object_close(): rawstor_cli_testio() below
 * runs no other queue activity while opening/closing (all its own I/O is
 * queued only after open() and awaited only before close()), so spinning
 * `queue` here to wait for the callback is safe. */
/* Shared by open_object()/close_object() below: rawstor_target_open()'s
 * opened object is written directly into the caller-supplied `object`
 * out-param (see open_object()), not routed through this struct, so
 * there's nothing left for open's own result to carry beyond what
 * close's already needs -- the two are identical. rawstor_target_open()/
 * rawstor_object_close() share the same ssize_t result callback shape
 * (negative -> -errno, zero -> success), so one trampoline suffices for
 * both. */
typedef struct {
    int error;
    int done;
} Result;

static int result_cb(ssize_t result, void* data) {
    Result* r = (Result*)data;
    r->error = result < 0 ? (int)-result : 0;
    r->done = 1;
    return 0;
}

static int
open_object(RawIOQueue* queue, const char* target, RawstorObject** object) {
    Result result = {0};
    int res = rawstor_target_open(queue, target, object, result_cb, &result);
    if (res < 0) {
        return res;
    }
    while (!result.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            return wres;
        }
    }
    if (result.error) {
        return -result.error;
    }
    return 0;
}

static int close_object(RawIOQueue* queue, RawstorObject* object) {
    Result result = {0};
    int res = rawstor_object_close(object, result_cb, &result);
    if (res < 0) {
        return res;
    }
    while (!result.done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            return wres;
        }
    }
    if (result.error) {
        return -result.error;
    }
    return 0;
}

int rawstor_cli_testio(
    unsigned int queue_size, const char* target, uint64_t block_size,
    unsigned int count, unsigned int io_depth, int vector_mode, int sync
) {
    int res;
    int err = 0;

    RawIOQueue* queue;
    res = rawio_queue_create(queue_size, &queue);
    if (res < 0) {
        fprintf(stderr, "rawio_queue_create() failed: %s\n", strerror(-res));
        err = -res;
        goto err_queue;
    }

    RawstorObject* object = NULL;
    res = open_object(queue, target, &object);
    if (res < 0) {
        fprintf(stderr, "rawstor_target_open() failed: %s\n", strerror(-res));
        err = -res;
        goto err_open;
    }

    unsigned int counter = count * io_depth;
    Worker** workers = calloc(io_depth, sizeof(Worker*));
    if (workers == NULL) {
        fprintf(stderr, "calloc() failed: %s\n", strerror(errno));
        err = errno;
        goto err_workers;
    }
    for (unsigned int i = 0; i < io_depth; ++i) {
        workers[i] =
            worker_create(object, i, block_size, &counter, count, sync);
        if (workers[i] == NULL) {
            fprintf(stderr, "worker_create() failed: %s\n", strerror(errno));
            err = errno;
            goto err_worker_create;
        }
    }

    if (!vector_mode) {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(
                workers[i]->src_iov.iov_base, workers[i]->src_iov.iov_len, i, 0
            );
            res = rawstor_object_pwrite(
                object, workers[i]->src_iov.iov_base,
                workers[i]->src_iov.iov_len, workers[i]->offset, sync,
                src_data_sent, workers[i]
            );
            if (res < 0) {
                fprintf(
                    stderr, "rawstor_object_pwrite() failed: %s\n",
                    strerror(-res)
                );
                err = -res;
                goto err_pwrite;
            }
        }
    } else {
        for (unsigned int i = 0; i < io_depth; ++i) {
            fill(
                workers[i]->src_iov.iov_base, workers[i]->src_iov.iov_len, i, 0
            );
            res = rawstor_object_pwritev(
                object, &workers[i]->src_iov, 1, workers[i]->src_iov.iov_len,
                workers[i]->offset, sync, srcv_data_sent, workers[i]
            );
            if (res < 0) {
                fprintf(
                    stderr, "rawstor_object_pwritev() failed: %s\n",
                    strerror(-res)
                );
                err = -res;
                goto err_pwrite;
            }
        }
    }

    while (counter > 0) {
        int res = rawio_wait(queue);
        if (res < 0) {
            fprintf(stderr, "rawstor_wait() failed: %s\n", strerror(-res));
            err = -res;
            goto err_wait;
        }
    }

    res = close_object(queue, object);
    if (res < 0) {
        fprintf(stderr, "rawstor_object_close() failed: %s\n", strerror(-res));
    }

    for (unsigned int i = 0; i < io_depth; ++i) {
        worker_delete(workers[i]);
    }
    free(workers);

    rawio_queue_delete(queue);

    printf("Success!\n");

    return EXIT_SUCCESS;

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
    res = close_object(queue, object);
    if (res < 0) {
        fprintf(stderr, "rawstor_object_close() failed: %s\n", strerror(-res));
    }
err_open:
    rawio_queue_delete(queue);
err_queue:
    return rawstd_exitcode_for_errno(err);
}
