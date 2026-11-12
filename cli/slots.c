#include "slots.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

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

/* The member's own role in the configuration its record holds. */
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

/* A ballot as "counter:proposer", the proposer in hexadecimal like a sync id.
 */
static void format_ballot(
    const struct RawstorObjectBallot* ballot, char* buf, size_t size
) {
    snprintf(
        buf, size, "%llu:%llx", (unsigned long long)ballot->counter,
        (unsigned long long)ballot->proposer
    );
}

/* rawstor_target_meta()'s own buffer capacity for one chunk's members, not
 * the number of chunks the object has -- slots_meta() below calls it once per
 * chunk, so this only ever needs to cover one chunk's width. */
enum { MAX_MEMBERS = 256 };

static int
slots_chunk(RawstorCliOp* op, const char* target, RawstorCliTable* table) {
    uint64_t offset;
    int offset_res = rawstor_target_offset(target, &offset);
    if (offset_res < 0) {
        return rawstd_exitcode_for_errno(-offset_res);
    }
    struct RawstorObjectMeta metas[MAX_MEMBERS];
    /* op is shared across every chunk in slots_meta()'s loop -- reset before
     * each reuse, or rawstor_cli_op_wait() sees the previous call's done flag
     * and returns its stale result without waiting for this one. */
    op->done = 0;
    int mres = rawstor_target_meta(
        op->queue, target, metas, MAX_MEMBERS, rawstor_cli_op_cb, op
    );
    ssize_t result = rawstor_cli_op_wait(op, mres);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_meta() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }
    if (result > MAX_MEMBERS) {
        fprintf(
            stderr,
            "rawstor slots: chunk[%llx] has %zd members, more than this CLI "
            "can display (%d)\n",
            (unsigned long long)offset, result, MAX_MEMBERS
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
        fprintf(stderr, "rawstor slots: slot and metadata counts differ\n");
        rawstor_string_list_delete(slots);
        return EXIT_FAILURE;
    }

    const char** slot = rawstor_string_list_iter(slots);
    for (ssize_t i = 0; i < result;
         i++, slot = rawstor_string_list_next(slot)) {
        const struct RawstorObjectMeta* meta = &metas[i];
        char slot_buf[32];
        snprintf(slot_buf, sizeof(slot_buf), "%zd", i);
        char slot_location[1024];
        rawstor_cli_target_location(
            *slot, slot_location, sizeof(slot_location)
        );
        RawstorCliCell cells[15] = {
            rawstor_cli_cell_size(offset),
            rawstor_cli_cell_string(target),
            rawstor_cli_cell_number(slot_buf, (uint64_t)i),
            rawstor_cli_cell_string(*slot),
            rawstor_cli_cell_string(slot_location),
        };
        char writers_buf[32];
        char epoch_buf[32];
        char sync_buf[512];
        char owner_buf[32];
        char promised_buf[64];
        char accepted_buf[64];
        if (meta->state == RAWSTOR_OBJECT_SYNC_STATE_UNREACHABLE) {
            cells[5] = rawstor_cli_cell_string(NULL);
            cells[6] = rawstor_cli_cell_number(NULL, 0);
            cells[7] = rawstor_cli_cell_string("UNREACHABLE");
            cells[8] = rawstor_cli_cell_string(NULL);
            cells[9] = rawstor_cli_cell_number(NULL, 0);
            cells[10] = rawstor_cli_cell_number(NULL, 0);
            cells[11] = rawstor_cli_cell_string(NULL);
            cells[12] = rawstor_cli_cell_string(NULL);
            cells[13] = rawstor_cli_cell_string(NULL);
            cells[14] = rawstor_cli_cell_string(NULL);
        } else {
            snprintf(
                writers_buf, sizeof(writers_buf), "%u",
                (unsigned int)meta->writers
            );
            snprintf(
                epoch_buf, sizeof(epoch_buf), "%llu",
                (unsigned long long)meta->config.epoch
            );
            format_sync_ids(&meta->config, sync_buf, sizeof(sync_buf));
            snprintf(
                owner_buf, sizeof(owner_buf), "%llx",
                (unsigned long long)meta->config.resync_owner
            );
            format_ballot(&meta->promised, promised_buf, sizeof(promised_buf));
            format_ballot(&meta->accepted, accepted_buf, sizeof(accepted_buf));
            cells[5] = rawstor_cli_cell_string(
                meta->member_role == RAWSTOR_MEMBER_WITNESS ? "witness" : "data"
            );
            cells[6] = rawstor_cli_cell_size(meta->spec.size);
            cells[7] =
                rawstor_cli_cell_string(sync_state_to_string(meta->state));
            cells[8] =
                rawstor_cli_cell_string(role_to_string(&meta->config, i));
            cells[9] = rawstor_cli_cell_number(writers_buf, meta->writers);
            cells[10] = rawstor_cli_cell_number(epoch_buf, meta->config.epoch);
            cells[11] = rawstor_cli_cell_string(sync_buf);
            cells[12] = rawstor_cli_cell_string(
                meta->config.resync_owner != 0 ? owner_buf : NULL
            );
            cells[13] = rawstor_cli_cell_string(promised_buf);
            cells[14] = rawstor_cli_cell_string(accepted_buf);
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

static int slots_meta(const char* target, RawstorCliTable* table) {
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
        ret = slots_chunk(&op, *it, table);
        if (ret != EXIT_SUCCESS) {
            break;
        }
    }

    rawstor_string_list_delete(chunks);
    rawstor_cli_op_destroy(&op);
    return ret;
}

int rawstor_cli_slots(const char* target, const RawstorCliOutput* output) {
    static const char* const columns[] = {
        "offset",        "chunk_target", "slot",     "slot_target",
        "slot_location", "member",       "size",     "state",
        "role",          "writers",      "epoch",    "sync_id",
        "resync_owner",  "promised",     "accepted",
    };
    static const enum RawstorCliColumnType types[] = {
        RAWSTOR_CLI_COLUMN_SIZE,   RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_NUMBER, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_SIZE,   RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_NUMBER,
        RAWSTOR_CLI_COLUMN_NUMBER, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING,
    };
    RawstorCliTable* table =
        rawstor_cli_table_create("slots", columns, types, 15);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    int ret = rawstor_cli_output_check(output, &table, 1);
    if (ret == EXIT_SUCCESS) {
        ret = slots_meta(target, table);
    }
    if (ret == EXIT_SUCCESS) {
        ret = rawstor_cli_output_print(output, &table, 1);
    }
    rawstor_cli_table_delete(table);
    return ret;
}
