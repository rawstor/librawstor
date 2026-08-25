#ifndef RAWSTOR_PYRAWSTOR_RAWIO_SYNC_H
#define RAWSTOR_PYRAWSTOR_RAWIO_SYNC_H

#include <rawstor/rawio.h>

#include <sys/types.h>

/* Shared by every py_rawstor_*() binding that drives one of the now-
 * asynchronous rawstor_target_*()/rawstor_location_*() calls to
 * completion synchronously: a RawIOQueue this whole call owns for its
 * own duration, pumped until the operation's own callback
 * (rawstor_sync_op_cb(), sharing `this` as its `data`) marks it done.
 * Deliberately a local duplicate of cli/rawio_sync.c's own struct of the
 * same shape, rather than a shared dependency -- pyrawstor is built via
 * setuptools, not this project's own autotools rules, so there's no
 * existing way for it to pull in a source file from cli/. */
typedef struct {
    RawIOQueue* queue;
    ssize_t result;
    int done;
} RawstorSyncOp;

/* Creates op->queue. Returns 0 on success, negative errno on failure. */
int rawstor_sync_op_init(RawstorSyncOp* op);

void rawstor_sync_op_destroy(RawstorSyncOp* op);

/* The int (*)(ssize_t result, void* data) callback every async call in
 * this file is issued with `op` as `data`. */
int rawstor_sync_op_cb(ssize_t result, void* data);

/* Pumps op->queue until op->done, then returns op->result. `res` is the
 * async call's own synchronous return value (0 if queued, negative on
 * immediate failure -- in which case op->cb never ran, and this returns
 * `res` unchanged without waiting). */
ssize_t rawstor_sync_op_wait(RawstorSyncOp* op, int res);

#endif /* RAWSTOR_PYRAWSTOR_RAWIO_SYNC_H */
