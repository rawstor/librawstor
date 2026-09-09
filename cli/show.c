#include "show.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char*
sync_state_to_string(enum RawstorObjectSyncStateValue state) {
    switch (state) {
    case RAWSTOR_OBJECT_SYNC_STATE_CLEAN:
        return "CLEAN";
    case RAWSTOR_OBJECT_SYNC_STATE_DIRTY:
        return "DIRTY";
    case RAWSTOR_OBJECT_SYNC_STATE_SYNCING:
        return "SYNCING";
    default:
        return "UNKNOWN";
    }
}

static void print_sync_id_history(const uint64_t* history, size_t count) {
    printf("sync_id_history:");
    int any = 0;
    for (size_t i = 0; i < count; i++) {
        if (history[i] == 0) {
            continue;
        }
        printf(" %" PRIu64, history[i]);
        any = 1;
    }
    if (!any) {
        printf(" none");
    }
    printf("\n");
}

static int show_meta(const char* target) {
    struct RawstorObjectMeta meta;

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int mres =
        rawstor_target_meta(op.queue, target, &meta, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, mres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_meta() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    printf("state: %s\n", sync_state_to_string(meta.sync_state.state));
    printf("epoch: %" PRIu64 "\n", meta.sync_state.epoch);
    printf("sync_id: %" PRIu64 "\n", meta.sync_state.sync_id);
    print_sync_id_history(
        meta.sync_state.sync_id_history, RAWSTOR_OBJECT_SYNC_ID_HISTORY
    );

    return EXIT_SUCCESS;
}

int rawstor_cli_show(const char* target, int verbose) {
    struct RawstorObjectSpec spec;

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres =
        rawstor_target_spec(op.queue, target, &spec, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_spec() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    char buf[256];
    rawstd_bytes_to_size(spec.size, buf, sizeof(buf));

    printf("target: %s\n", target);
    printf("size: %s\n", buf);
    printf("mirrors: %u\n", spec.mirrors);

    if (!verbose) {
        return EXIT_SUCCESS;
    }

    return show_meta(target);
}
