#include "snapshot.h"

#include "rawio_sync.h"
#include "target_snapshot.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_snapshot(const char* target) {
    fprintf(stderr, "Taking a snapshot of: %s\n", target);

    struct RawstdUUID id;
    int res = rawstd_uuid7_init(&id);
    if (res < 0) {
        fprintf(
            stderr, "Failed to generate a snapshot id: %s\n", strerror(-res)
        );
        return rawstd_exitcode_for_errno(-res);
    }
    RawstdUUIDString snapshot_id;
    rawstd_uuid_to_string(&id, &snapshot_id);

    char bound_target[65536];
    res = rawstor_cli_bind_snapshot_id(
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

    /* NULL: spec is meaningless for a CoW snapshot. */
    int sres = rawstor_target_create(
        op.queue, bound_target, NULL, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Snapshot created\n");
    fprintf(stdout, "%s\n", snapshot_id);

    return EXIT_SUCCESS;
}
