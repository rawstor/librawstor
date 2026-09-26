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
    case RAWSTOR_OBJECT_SYNC_STATE_SYNCING:
        return "SYNCING";
    default:
        return "UNKNOWN";
    }
}

/* Hex, not decimal -- same base sync_id is printed in below, matching
 * meta_encode()'s own on-disk encoding of both fields (blk_backend.cpp).
 */
static void print_sync_id_history(
    const char* indent, const uint64_t* history, size_t count
) {
    printf("%ssync_id_history:", indent);
    int any = 0;
    for (size_t i = 0; i < count; i++) {
        if (history[i] == 0) {
            continue;
        }
        printf(" %llx", (unsigned long long)history[i]);
        any = 1;
    }
    if (!any) {
        printf(" none");
    }
    printf("\n");
}

/* rawstor_target_meta()'s own buffer capacity for one chunk's own
 * mirrors, not the number of chunks the object has -- show_meta() below
 * calls it once per chunk (rawstor_cli_chunk_count()), so this only ever
 * needs to cover one chunk's own width, not the whole object at once. */
enum { MAX_MIRRORS = 256 };

/* How many distinct chunks `target` actually names, from a caller of
 * rawstor_target_meta()'s own point of view: `spec`'s own size/chunk_size
 * describe the object's real shape the same way MultiChunkObject routes
 * I/O by it (chunk_size == 0 meaning the ordinary, single-chunk case
 * every plain target is), but for an mds:// target that real shape isn't
 * reflected in `target`'s own flat URI list at all -- rawstor_target_meta()
 * itself only ever accepts offset 0 there (its own doc comment) even
 * though spec.size/chunk_size describe a real, multi-chunk object. So
 * before trusting size/chunk_size to decide how many chunk[N] blocks to
 * print, cross-check that `target`'s own URI count actually equals
 * chunk_count * spec->width -- every chunk of a target this call can
 * really address carries exactly that many URIs (Target::create()'s own
 * validation); if it doesn't, `target` isn't decomposable at this level,
 * so treat it as a single, opaque chunk instead. */
static uint64_t rawstor_cli_chunk_count(
    const char* target, const struct RawstorObjectSpec* spec
) {
    uint64_t chunk_count =
        spec->chunk_size == 0
            ? 1
            : (spec->size + spec->chunk_size - 1) / spec->chunk_size;
    if (chunk_count <= 1 || spec->width == 0) {
        return 1;
    }

    size_t uri_count = 1;
    for (const char* p = target; *p != '\0'; p++) {
        if (*p == ',') {
            uri_count++;
        }
    }
    if (uri_count != (size_t)chunk_count * spec->width) {
        return 1;
    }
    return chunk_count;
}

static int
show_chunk_meta(RawstorCliOp* op, const char* target, uint64_t offset) {
    struct RawstorObjectMeta metas[MAX_MIRRORS];
    /* op is shared across every chunk in show_meta()'s own loop below --
     * reset before each reuse, same convention as cli/info.c's own
     * multi-call loops, or rawstor_cli_op_wait() sees the previous
     * chunk's own already-done flag and returns its stale result without
     * actually waiting for this call's completion. */
    op->done = 0;
    int mres = rawstor_target_meta(
        op->queue, target, offset, metas, MAX_MIRRORS, rawstor_cli_op_cb, op
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

    /* offset, not an index -- the same value `rawstor resolve`'s own
     * --offset takes, and target's own comma-separated order, not a
     * value this command has to re-parse target to print. Hex, not
     * decimal -- same base the offset segment itself uses in a target
     * string (parse_target_path()'s own doc comment, target.hpp). */
    printf("chunk[%llx]:\n", (unsigned long long)offset);
    for (ssize_t i = 0; i < result; i++) {
        const struct RawstorObjectMeta* meta = &metas[i];
        printf("  mirror[%zd]:\n", i);
        if (meta->sync_state.state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            printf("    unreachable\n");
        } else {
            char buf[256];
            rawstd_bytes_to_size(meta->spec.size, buf, sizeof(buf));
            printf("    size: %s\n", buf);
            printf("    mirrors: %u\n", meta->spec.width);
            printf(
                "    state: %s\n", sync_state_to_string(meta->sync_state.state)
            );
            printf(
                "    epoch: %llu\n", (unsigned long long)meta->sync_state.epoch
            );
            printf(
                "    sync_id: %llx\n",
                (unsigned long long)meta->sync_state.sync_id
            );
            print_sync_id_history(
                "    ", meta->sync_state.sync_id_history,
                RAWSTOR_OBJECT_SYNC_ID_HISTORY
            );
        }
    }

    return EXIT_SUCCESS;
}

static int show_meta(const char* target, const struct RawstorObjectSpec* spec) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    uint64_t chunk_count = rawstor_cli_chunk_count(target, spec);
    int ret = EXIT_SUCCESS;
    for (uint64_t i = 0; i < chunk_count; i++) {
        ret = show_chunk_meta(&op, target, i * spec->chunk_size);
        if (ret != EXIT_SUCCESS) {
            break;
        }
    }

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

    return show_meta(target, &spec);
}
