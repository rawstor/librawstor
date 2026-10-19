#include "show.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <errno.h>
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
    case RAWSTOR_OBJECT_SYNC_STATE_LOST:
        return "LOST";
    default:
        return "UNKNOWN";
    }
}

/* The mirror's own role in the configuration its record holds. */
static const char*
role_to_string(const struct RawstorObjectConfig* config, ssize_t index) {
    if (index >= (ssize_t)config->nroles) {
        return NULL;
    }
    switch (config->roles[index]) {
    case RAWSTOR_OBJECT_MEMBER_IN_SYNC:
        return "IN_SYNC";
    case RAWSTOR_OBJECT_MEMBER_SYNCING:
        return "SYNCING";
    case RAWSTOR_OBJECT_MEMBER_EXCLUDED:
        return "EXCLUDED";
    default:
        return NULL;
    }
}

/* Stored ancestors are newest first; display the lineage oldest first,
 * followed by the current sync id. All ids use hexadecimal notation. */
static void print_sync_ids(const struct RawstorObjectConfig* config) {
    printf("    sync_id:");
    for (size_t i = RAWSTOR_OBJECT_SYNC_ID_HISTORY; i > 0; --i) {
        uint64_t id = config->sync_id_history[i - 1];
        if (id != 0) {
            printf(" %llx", (unsigned long long)id);
        }
    }
    printf(" %llx\n", (unsigned long long)config->sync_id);
}

/* rawstor_target_meta()'s own buffer capacity for one chunk's own
 * mirrors, not the number of chunks the object has -- show_meta() below
 * calls it once per chunk (count_chunks()), so this only ever
 * needs to cover one chunk's own width, not the whole object at once. */
enum { MAX_MIRRORS = 256 };

static int show_chunk_meta(RawstorCliOp* op, const char* target) {
    uint64_t offset;
    int offset_res = rawstor_target_offset(target, &offset);
    if (offset_res < 0) {
        return rawstd_exitcode_for_errno(-offset_res);
    }
    struct RawstorObjectMeta metas[MAX_MIRRORS];
    /* op is shared across every chunk in show_meta()'s own loop below --
     * reset before each reuse, same convention as cli/info.c's own
     * multi-call loops, or rawstor_cli_op_wait() sees the previous
     * chunk's own already-done flag and returns its stale result without
     * actually waiting for this call's completion. */
    op->done = 0;
    int mres = rawstor_target_meta(
        op->queue, target, metas, MAX_MIRRORS, rawstor_cli_op_cb, op
    );
    ssize_t result = rawstor_cli_op_wait(op, mres);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_meta() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }
    if (result > MAX_MIRRORS) {
        fprintf(
            stderr,
            "rawstor show -v: chunk[%llx] has %zd mirrors, more "
            "than this CLI can display (%d)\n",
            (unsigned long long)offset, result, MAX_MIRRORS
        );
        return EXIT_FAILURE;
    }

    RawstorStringList* slots = NULL;
    op->done = 0;
    ssize_t slot_count = rawstor_cli_op_wait(
        op,
        rawstor_target_slots(op->queue, target, &slots, rawstor_cli_op_cb, op)
    );
    if (slot_count < 0) {
        fprintf(
            stderr, "rawstor_target_slots() failed: %s\n",
            strerror((int)-slot_count)
        );
        return rawstd_exitcode_for_errno((int)-slot_count);
    }
    if (slot_count != result) {
        fprintf(stderr, "rawstor show -v: slot and metadata counts differ\n");
        rawstor_string_list_delete(slots);
        return EXIT_FAILURE;
    }

    printf("chunk[%llx]:\n", (unsigned long long)offset);
    printf("  target: %s\n", target);
    const char** slot = rawstor_string_list_iter(slots);
    for (ssize_t i = 0; i < result;
         i++, slot = rawstor_string_list_next(slot)) {
        const struct RawstorObjectMeta* meta = &metas[i];
        printf("  mirror[%zd]:\n", i);
        printf("    target: %s\n", *slot);
        if (meta->state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            printf("    unreachable\n");
        } else {
            char buf[256];
            rawstd_bytes_to_size(meta->spec.size, buf, sizeof(buf));
            printf(
                "    member: %s\n",
                meta->member_role == RAWSTOR_MEMBER_WITNESS ? "witness" : "data"
            );
            printf("    size: %s\n", buf);
            printf("    state: %s\n", sync_state_to_string(meta->state));
            const char* role = role_to_string(&meta->config, i);
            if (role != NULL) {
                printf("    role: %s\n", role);
            }
            printf("    epoch: %llu\n", (unsigned long long)meta->config.epoch);
            print_sync_ids(&meta->config);
        }
    }

    rawstor_string_list_delete(slots);
    return EXIT_SUCCESS;
}

static int show_meta(const char* target) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* chunks = NULL;
    ssize_t chunk_count = rawstor_cli_op_chunks(&op, target, &chunks);
    if (chunk_count < 0) {
        fprintf(
            stderr, "rawstor_target_chunks() failed: %s\n",
            strerror((int)-chunk_count)
        );
        rawstor_cli_op_destroy(&op);
        return rawstd_exitcode_for_errno((int)-chunk_count);
    }

    int ret = EXIT_SUCCESS;
    for (const char** it = rawstor_string_list_iter(chunks); it != NULL;
         it = rawstor_string_list_next(it)) {
        ret = show_chunk_meta(&op, *it);
        if (ret != EXIT_SUCCESS) {
            break;
        }
    }

    rawstor_string_list_delete(chunks);
    rawstor_cli_op_destroy(&op);
    return ret;
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
