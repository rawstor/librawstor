#include "chunks.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The row of one chunk: its offset, its target, its own size, how many data
 * copies it keeps and how many member slots it has (a witness is a slot but
 * not a copy). */
static int
chunks_row(RawstorCliOp* op, const char* chunk, RawstorCliTable* table) {
    uint64_t offset;
    int offset_res = rawstor_target_offset(chunk, &offset);
    if (offset_res < 0) {
        fprintf(
            stderr, "rawstor_target_offset() failed: %s\n",
            strerror(-offset_res)
        );
        return rawstd_exitcode_for_errno(-offset_res);
    }

    struct RawstorObjectSpec spec;
    op->done = 0;
    ssize_t result = rawstor_cli_op_wait(
        op, rawstor_target_spec(op->queue, chunk, &spec, rawstor_cli_op_cb, op)
    );
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_spec() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    RawstorStringList* slots = NULL;
    op->done = 0;
    ssize_t slot_count = rawstor_cli_op_wait(
        op,
        rawstor_target_slots(op->queue, chunk, &slots, rawstor_cli_op_cb, op)
    );
    if (slot_count < 0) {
        fprintf(
            stderr, "rawstor_target_slots() failed: %s\n",
            strerror((int)-slot_count)
        );
        return rawstd_exitcode_for_errno((int)-slot_count);
    }
    rawstor_string_list_delete(slots);

    char chunk_buf[32];
    char mirrors_buf[32];
    char slots_buf[32];
    snprintf(chunk_buf, sizeof(chunk_buf), "%llx", (unsigned long long)offset);
    snprintf(mirrors_buf, sizeof(mirrors_buf), "%u", spec.width);
    snprintf(slots_buf, sizeof(slots_buf), "%zd", slot_count);
    RawstorCliCell cells[] = {
        rawstor_cli_cell_string(chunk_buf),
        rawstor_cli_cell_string(chunk),
        rawstor_cli_cell_size(spec.size),
        rawstor_cli_cell_number(mirrors_buf, spec.width),
        rawstor_cli_cell_number(slots_buf, (uint64_t)slot_count),
    };
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}

int rawstor_cli_chunks(const char* target, const RawstorCliOutput* output) {
    static const char* const columns[] = {
        "chunk", "chunk_target", "size", "mirrors", "slots"
    };
    static const enum RawstorCliColumnType types[] = {
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_SIZE, RAWSTOR_CLI_COLUMN_NUMBER,
        RAWSTOR_CLI_COLUMN_NUMBER
    };
    RawstorCliTable* table =
        rawstor_cli_table_create("chunks", columns, types, 5);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    int ret = rawstor_cli_output_check(output, &table, 1);
    if (ret != EXIT_SUCCESS) {
        rawstor_cli_table_delete(table);
        return ret;
    }

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        rawstor_cli_table_delete(table);
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
        rawstor_cli_table_delete(table);
        return rawstd_exitcode_for_errno((int)-chunk_count);
    }

    for (const char** it = rawstor_string_list_iter(chunks); it != NULL;
         it = rawstor_string_list_next(it)) {
        ret = chunks_row(&op, *it, table);
        if (ret != EXIT_SUCCESS) {
            break;
        }
    }
    rawstor_string_list_delete(chunks);
    rawstor_cli_op_destroy(&op);

    if (ret == EXIT_SUCCESS) {
        ret = rawstor_cli_output_print(output, &table, 1);
    }
    rawstor_cli_table_delete(table);
    return ret;
}
