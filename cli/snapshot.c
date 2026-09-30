#include "snapshot.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// One rawstor_target_create_snapshot() attempt against a fresh queue,
// driven to completion synchronously -- returns its own result unchanged
// (the snapshot target string's own length on success, negative errno on
// failure; rawstor_cli_op_init()'s own failure already comes back in that
// same shape, a negative errno).
static ssize_t try_create_snapshot(
    const char* target, const char* uuid, char* snapshot_target, size_t size
) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        return res;
    }

    int sres = rawstor_target_create_snapshot(
        op.queue, target, uuid, snapshot_target, size, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    return result;
}

int rawstor_cli_snapshot(const char* target, const char* uuid) {
    fprintf(stderr, "Taking a snapshot of: %s\n", target);

    /* `uuid` NULL: the version id is either already bound in `target`'s
     * own path, or generated fresh -- see rawstor_target_create_snapshot(). */

    // NULL/0 asks for the snapshot target string's own length alone --
    // the same snprintf(NULL, 0, ...) idiom rawstor_target_create_snapshot()
    // itself just forwards to (target.cpp), needing no I/O and creating
    // nothing. The second call, into a buffer sized exactly for that
    // length, does the real snapshot.
    ssize_t result = try_create_snapshot(target, uuid, NULL, 0);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create_snapshot() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    char* snapshot_target = malloc((size_t)result + 1);
    if (snapshot_target == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    result =
        try_create_snapshot(target, uuid, snapshot_target, (size_t)result + 1);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create_snapshot() failed: %s\n",
            strerror((int)-result)
        );
        free(snapshot_target);
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Snapshot created\n");
    fprintf(stdout, "%s\n", snapshot_target);

    free(snapshot_target);

    return EXIT_SUCCESS;
}

int rawstor_cli_list_snapshots(const char* target) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* snapshots = NULL;
    int sres = rawstor_target_snapshots(
        op.queue, target, &snapshots, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_snapshots() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    for (const char** it = rawstor_string_list_iter(snapshots); it != NULL;
         it = rawstor_string_list_next(it)) {
        printf("%s\n", *it);
    }
    rawstor_string_list_delete(snapshots);
    return EXIT_SUCCESS;
}
