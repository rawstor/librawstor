#include "rawio_sync.h"

#include <stddef.h>

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
