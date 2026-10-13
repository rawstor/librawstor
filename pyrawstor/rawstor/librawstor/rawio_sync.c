#include "rawio_sync.h"

#include <rawstor/target.h>
#include <stddef.h>

int rawstor_sync_op_init(RawstorSyncOp* op) {
    op->result = 0;
    op->done = 0;

    /* Metadata operations fan out over the complete member set. */
    return rawio_queue_create(2 * RAWSTOR_OBJECT_MAX_WIDTH + 2, &op->queue);
}

void rawstor_sync_op_destroy(RawstorSyncOp* op) {
    rawio_queue_delete(op->queue);
}

int rawstor_sync_op_cb(ssize_t result, void* data) {
    RawstorSyncOp* op = (RawstorSyncOp*)data;
    op->result = result;
    op->done = 1;
    return 0;
}

ssize_t rawstor_sync_op_wait(RawstorSyncOp* op, int res) {
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
