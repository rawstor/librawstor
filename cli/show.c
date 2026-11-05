#include "show.h"

#include "output.h"
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
        return "UNKNOWN";
    }
    switch (config->roles[index]) {
    case RAWSTOR_OBJECT_MEMBER_IN_SYNC:
        return "IN_SYNC";
    case RAWSTOR_OBJECT_MEMBER_SYNCING:
        return "SYNCING";
    case RAWSTOR_OBJECT_MEMBER_EXCLUDED:
        return "EXCLUDED";
    default:
        return "UNKNOWN";
    }
}

/* Stored ancestors are newest first; the lineage is written oldest first,
 * followed by the current sync id, space-separated. All ids use hexadecimal
 * notation. */
static void format_sync_ids(
    const struct RawstorObjectConfig* config, char* buf, size_t size
) {
    size_t len = 0;
    buf[0] = '\0';
    for (size_t i = RAWSTOR_OBJECT_SYNC_ID_HISTORY; i > 0; --i) {
        uint64_t id = config->sync_id_history[i - 1];
        if (id != 0 && len < size) {
            len += (size_t)snprintf(
                buf + len, size - len, "%llx ", (unsigned long long)id
            );
        }
    }
    if (len < size) {
        snprintf(
            buf + len, size - len, "%llx", (unsigned long long)config->sync_id
        );
    }
}

/* rawstor_target_meta()'s own buffer capacity for one chunk's own
 * mirrors, not the number of chunks the object has -- show_meta() below
 * calls it once per chunk (count_chunks()), so this only ever
 * needs to cover one chunk's own width, not the whole object at once. */
enum { MAX_MIRRORS = 256 };

static int
show_chunk_meta(RawstorCliOp* op, const char* target, RawstorCliTable* table) {
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

    char chunk_buf[32];
    snprintf(chunk_buf, sizeof(chunk_buf), "%llx", (unsigned long long)offset);
    const char** slot = rawstor_string_list_iter(slots);
    for (ssize_t i = 0; i < result;
         i++, slot = rawstor_string_list_next(slot)) {
        const struct RawstorObjectMeta* meta = &metas[i];
        RawstorCliCell cells[10] = {
            rawstor_cli_cell_string(chunk_buf),
            rawstor_cli_cell_string(target),
            rawstor_cli_cell_number(NULL, (uint64_t)i),
            rawstor_cli_cell_string(*slot),
        };
        char slot_buf[32];
        snprintf(slot_buf, sizeof(slot_buf), "%zd", i);
        cells[2].text = slot_buf;
        char epoch_buf[32];
        char sync_buf[512];
        if (meta->state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            cells[4] = rawstor_cli_cell_string(NULL);
            cells[5] = rawstor_cli_cell_number(NULL, 0);
            cells[6] = rawstor_cli_cell_string("UNREACHABLE");
            cells[7] = rawstor_cli_cell_string(NULL);
            cells[8] = rawstor_cli_cell_number(NULL, 0);
            cells[9] = rawstor_cli_cell_string(NULL);
        } else {
            snprintf(
                epoch_buf, sizeof(epoch_buf), "%llu",
                (unsigned long long)meta->config.epoch
            );
            format_sync_ids(&meta->config, sync_buf, sizeof(sync_buf));
            cells[4] = rawstor_cli_cell_string(
                meta->member_role == RAWSTOR_MEMBER_WITNESS ? "witness" : "data"
            );
            cells[5] = rawstor_cli_cell_size(meta->spec.size);
            cells[6] =
                rawstor_cli_cell_string(sync_state_to_string(meta->state));
            cells[7] =
                rawstor_cli_cell_string(role_to_string(&meta->config, i));
            cells[8] = rawstor_cli_cell_number(epoch_buf, meta->config.epoch);
            cells[9] = rawstor_cli_cell_string(sync_buf);
        }
        if (rawstor_cli_table_add_row(table, cells) < 0) {
            fprintf(stderr, "Out of memory\n");
            rawstor_string_list_delete(slots);
            return EXIT_FAILURE;
        }
    }

    rawstor_string_list_delete(slots);
    return EXIT_SUCCESS;
}

static int show_meta(const char* target, RawstorCliTable* table) {
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
        ret = show_chunk_meta(&op, *it, table);
        if (ret != EXIT_SUCCESS) {
            break;
        }
    }

    rawstor_string_list_delete(chunks);
    rawstor_cli_op_destroy(&op);
    return ret;
}

int rawstor_cli_show(
    const char* target, int verbose, const RawstorCliOutput* output
) {
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

    /* version_id is a column only when TARGET names a version. */
    char object_id[64];
    char version_id[64];
    rawstor_cli_target_ids(
        target, object_id, sizeof(object_id), version_id, sizeof(version_id)
    );
    int has_version = version_id[0] != '\0';
    static const char* const version_object_columns[] = {
        "object_id", "version_id", "target", "size", "mirrors"
    };
    static const enum RawstorCliColumnType version_object_types[] = {
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_SIZE,
        RAWSTOR_CLI_COLUMN_NUMBER
    };
    static const char* const live_object_columns[] = {
        "object_id", "target", "size", "mirrors"
    };
    static const enum RawstorCliColumnType live_object_types[] = {
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_SIZE, RAWSTOR_CLI_COLUMN_NUMBER
    };
    static const char* const mirror_columns[] = {
        "chunk", "chunk_target", "slot", "slot_target", "member",
        "size",  "state",        "role", "epoch",       "sync_id",
    };
    static const enum RawstorCliColumnType mirror_types[] = {
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_NUMBER, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_SIZE,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_NUMBER, RAWSTOR_CLI_COLUMN_STRING,
    };

    RawstorCliTable* tables[2] = {NULL, NULL};
    size_t ntables = 1;
    int ret = EXIT_FAILURE;
    tables[0] =
        has_version
            ? rawstor_cli_record_create(
                  "object", version_object_columns, version_object_types, 5
              )
            : rawstor_cli_record_create(
                  "object", live_object_columns, live_object_types, 4
              );
    if (verbose) {
        tables[1] = rawstor_cli_table_create(
            "chunks", mirror_columns, mirror_types, 10
        );
        if (tables[1] != NULL) {
            /* chunk and chunk_target identify a chunk; the rest of a row
             * is one of its members. */
            rawstor_cli_table_group(tables[1], 2, "members");
        }
        ntables = 2;
    }
    if (tables[0] == NULL || (verbose && tables[1] == NULL)) {
        fprintf(stderr, "Out of memory\n");
        goto out;
    }

    char mirrors_buf[32];
    snprintf(mirrors_buf, sizeof(mirrors_buf), "%u", spec.width);
    RawstorCliCell cells[5];
    size_t ncells = 0;
    cells[ncells++] = rawstor_cli_cell_string(object_id);
    if (has_version) {
        cells[ncells++] = rawstor_cli_cell_string(version_id);
    }
    cells[ncells++] = rawstor_cli_cell_string(target);
    cells[ncells++] = rawstor_cli_cell_size(spec.size);
    cells[ncells++] = rawstor_cli_cell_number(mirrors_buf, spec.width);
    if (rawstor_cli_table_add_row(tables[0], cells) < 0) {
        fprintf(stderr, "Out of memory\n");
        goto out;
    }

    if (verbose) {
        ret = show_meta(target, tables[1]);
        if (ret != EXIT_SUCCESS) {
            goto out;
        }
    }
    ret = rawstor_cli_output_print(output, tables, ntables);

out:
    for (size_t i = 0; i < 2; ++i) {
        if (tables[i] != NULL) {
            rawstor_cli_table_delete(tables[i]);
        }
    }
    return ret;
}
