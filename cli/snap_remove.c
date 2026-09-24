#include "snap_remove.h"

#include "rawio_sync.h"
#include "target_snapshot.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_snap_remove(const char* target, const char* snapshot_id) {
    fprintf(stderr, "Removing snapshot %s of: %s\n", snapshot_id, target);

    char bound_target[65536];
    int res = rawstor_cli_bind_snapshot_id(
        target, snapshot_id, bound_target, sizeof(bound_target)
    );
    if (res < 0) {
        fprintf(stderr, "Target too long: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorCliOp op;
    res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres =
        rawstor_target_remove(op.queue, bound_target, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_remove() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Snapshot removed\n");

    return EXIT_SUCCESS;
}
