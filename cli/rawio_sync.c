#include "rawio_sync.h"

#include <rawstor.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>

int rawstor_cli_op_init(RawstorCliOp* op) {
    op->result = 0;
    op->done = 0;

    /* A rawstor_target_*()/rawstor_location_*() call can fan out across
     * several comma-separated backends concurrently, each needing more
     * than one SQE in flight at once (connect, a background recv-pump
     * registration, the request itself, retry backoff timers, ...) --
     * a too-small queue makes io_uring_get_sqe() return null (ENOBUFS)
     * under perfectly ordinary multi-backend use. 128 is generous
     * headroom for this CLI's own light, one-shot-per-invocation usage
     * (unlike testio's own --queue-size, sized for sustained I/O-depth
     * throughput). */
    return rawio_queue_create(128, &op->queue);
}

void rawstor_cli_op_destroy(RawstorCliOp* op) {
    rawio_queue_delete(op->queue);
}

int rawstor_cli_op_cb(ssize_t result, void* data) {
    RawstorCliOp* op = (RawstorCliOp*)data;
    op->result = result;
    op->done = 1;
    return 0;
}

ssize_t rawstor_cli_op_wait(RawstorCliOp* op, int res) {
    if (res < 0) {
        return res;
    }

    while (!op->done) {
        int wres = rawio_wait(op->queue);
        if (wres < 0) {
            return wres;
        }
    }

    return op->result;
}

ssize_t rawstor_cli_op_chunks(
    RawstorCliOp* op, const char* target, uint64_t** offsets
) {
    *offsets = NULL;

    op->done = 0;
    ssize_t count = rawstor_cli_op_wait(
        op,
        rawstor_target_chunks(op->queue, target, NULL, 0, rawstor_cli_op_cb, op)
    );
    if (count <= 0) {
        return count;
    }

    uint64_t* buf = malloc((size_t)count * sizeof(*buf));
    if (buf == NULL) {
        return -ENOMEM;
    }

    op->done = 0;
    ssize_t filled = rawstor_cli_op_wait(
        op, rawstor_target_chunks(
                op->queue, target, buf, (size_t)count, rawstor_cli_op_cb, op
            )
    );
    if (filled < 0) {
        free(buf);
        return filled;
    }
    /* The object may have grown between the two calls; only the first
     * `count` entries were written. */
    if (filled > count) {
        filled = count;
    }

    *offsets = buf;
    return filled;
}
