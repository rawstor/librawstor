#include "snapshot.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

int rawstor_cli_snapshot(const char* target) {
    fprintf(stderr, "Taking a snapshot of: %s\n", target);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstdUUIDString snapshot_id;
    int sres = rawstor_target_create_snapshot(
        op.queue, target, NULL, snapshot_id, sizeof(snapshot_id),
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

    if (sres >= (int)sizeof(snapshot_id)) {
        fprintf(stderr, "rawstor_target_create_snapshot(): output truncated\n");
        return EX_SOFTWARE;
    }

    fprintf(stderr, "Snapshot created\n");
    fprintf(stdout, "%s\n", snapshot_id);

    return EXIT_SUCCESS;
}
