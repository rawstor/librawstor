#include "show.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <errno.h>
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

static void print_sync_id_history(
    const char* indent, const uint64_t* history, size_t count
) {
    printf("%ssync_id_history:", indent);
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

/* rawstor_target_meta()'s own buffer capacity, not the number of URIs in
 * `target` -- a `result` greater than this means the CLI itself can't
 * display that many slots, not that the call failed (see its own doc
 * comment: same truncation convention as rawstor_target_id()/
 * _location()). One slot per URI (docs/locations_and_targets.md) -- a
 * multi-chunk target names one per chunk, not just one per mirror copy,
 * so this has to cover an object with many chunks, not just a wide
 * mirror set. Large enough that the backing array below is heap-, not
 * stack-allocated. */
enum { MAX_SLOTS = 65536 };

static int show_meta(const char* target) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    struct RawstorObjectMeta* metas = calloc(MAX_SLOTS, sizeof(*metas));
    if (metas == NULL) {
        fprintf(stderr, "calloc() failed: %s\n", strerror(errno));
        rawstor_cli_op_destroy(&op);
        return rawstd_exitcode_for_errno(errno);
    }

    int mres = rawstor_target_meta(
        op.queue, target, metas, MAX_SLOTS, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, mres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        int err = (int)-result;
        free(metas);
        fprintf(stderr, "rawstor_target_meta() failed: %s\n", strerror(err));
        return rawstd_exitcode_for_errno(err);
    }
    if (result > MAX_SLOTS) {
        free(metas);
        fprintf(
            stderr,
            "rawstor show -v: %zd slots, more than this CLI can display "
            "(%d)\n",
            result, MAX_SLOTS
        );
        return EXIT_FAILURE;
    }

    for (ssize_t i = 0; i < result; i++) {
        const struct RawstorObjectMeta* meta = &metas[i];
        /* Index, not the URI itself -- the same index `rawstor resolve`'s
         * own --winner takes, and target's own comma-separated order, not
         * a value this command has to re-parse target to print. One slot
         * per URI, not per mirror copy -- a multi-chunk target's own
         * slots are different chunks, not different copies of the same
         * one, so "mirror" would misname most of them. */
        printf("slot[%zd]:\n", i);
        if (meta->sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            printf("  unreachable\n");
        } else {
            char buf[256];
            rawstd_bytes_to_size(meta->spec.size, buf, sizeof(buf));
            printf("  size: %s\n", buf);
            printf("  mirrors: %u\n", meta->spec.width);
            printf(
                "  state: %s\n", sync_state_to_string(meta->sync_state.state)
            );
            printf("  epoch: %" PRIu64 "\n", meta->sync_state.epoch);
            printf("  sync_id: %" PRIu64 "\n", meta->sync_state.sync_id);
            print_sync_id_history(
                "  ", meta->sync_state.sync_id_history,
                RAWSTOR_OBJECT_SYNC_ID_HISTORY
            );
        }
    }

    free(metas);
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
    printf("mirrors: %u\n", spec.width);

    if (!verbose) {
        return EXIT_SUCCESS;
    }

    return show_meta(target);
}
