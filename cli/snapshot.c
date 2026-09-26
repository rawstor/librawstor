#include "snapshot.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

int rawstor_cli_snapshot(const char* target, const char* uuid) {
    fprintf(stderr, "Taking a snapshot of: %s\n", target);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    /* `uuid` NULL: the version id is either already bound in `target`'s
     * own path, or generated fresh -- see rawstor_target_create_snapshot(). */
    char snapshot_target[65536];
    int sres = rawstor_target_create_snapshot(
        op.queue, target, uuid, snapshot_target, sizeof(snapshot_target),
        rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create_snapshot() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }
    if (result >= (ssize_t)sizeof(snapshot_target)) {
        fprintf(stderr, "rawstor_target_create_snapshot(): output truncated\n");
        return EX_SOFTWARE;
    }

    fprintf(stderr, "Snapshot created\n");
    fprintf(stdout, "%s\n", snapshot_target);

    return EXIT_SUCCESS;
}
