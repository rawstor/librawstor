#include "snapshot.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_snapshot(const char* target) {
    fprintf(stderr, "Snapshotting object: %s\n", target);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    /* NULL: this call generates a fresh version id itself. */
    char snap_id[64];
    int sres = rawstor_target_snapshot_create(
        op.queue, target, NULL, snap_id, sizeof(snap_id), rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_snapshot_create() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Snapshot created: %s\n", snap_id);
    fprintf(stdout, "%s\n", snap_id);

    return EXIT_SUCCESS;
}
