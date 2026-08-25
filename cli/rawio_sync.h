#ifndef RAWSTOR_CLI_RAWIO_SYNC_H
#define RAWSTOR_CLI_RAWIO_SYNC_H

#include <rawstor/rawio.h>

#include <sys/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Shared by every cli command that drives one of the now-asynchronous
 * rawstor_target_*()/rawstor_location_*() calls to completion
 * synchronously: a RawIOQueue this whole call owns for its own duration,
 * pumped until the operation's own callback (rawstor_cli_op_cb(), sharing
 * `this` as its `data`) marks it done. */
typedef struct {
    RawIOQueue* queue;
    ssize_t result;
    int done;
} RawstorCliOp;

/* Creates op->queue. Returns 0 on success, negative errno on failure. */
int rawstor_cli_op_init(RawstorCliOp* op);

void rawstor_cli_op_destroy(RawstorCliOp* op);

/* The int (*)(ssize_t result, void* data) callback every async call in
 * this file is issued with `op` as `data`. */
int rawstor_cli_op_cb(ssize_t result, void* data);

/* Pumps op->queue until op->done, then returns op->result. `res` is the
 * async call's own synchronous return value (0 if queued, negative on
 * immediate failure -- in which case op->cb never ran, and this returns
 * `res` unchanged without waiting). */
ssize_t rawstor_cli_op_wait(RawstorCliOp* op, int res);

#ifdef __cplusplus
}
#endif

#endif /* RAWSTOR_CLI_RAWIO_SYNC_H */
