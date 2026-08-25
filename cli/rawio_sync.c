#include "rawio_sync.h"

#include <stddef.h>

int rawstor_cli_op_init(RawstorCliOp* op) {
    op->result = 0;
    op->done = 0;

    return rawio_queue_create(2, &op->queue);
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
