#include "list.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const columns[] = {"object_id", "target", "location"};
static const enum RawstorCliColumnType types[] = {
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING
};

int rawstor_cli_list(const char* location, const RawstorCliOutput* output) {
    RawstorCliTable* table =
        rawstor_cli_table_create("targets", columns, types, 3);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        rawstor_cli_table_delete(table);
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    do {
        op.done = 0;
        int sres = rawstor_location_list(
            op.queue, location, 0, &targets, &token, rawstor_cli_op_cb, &op
        );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result < 0) {
            fprintf(
                stderr, "rawstor_location_list() failed: %s\n",
                strerror((int)-result)
            );
            rawstor_cli_op_destroy(&op);
            rawstor_cli_table_delete(table);
            return rawstd_exitcode_for_errno((int)-result);
        }
        for (const char** it = rawstor_string_list_iter(targets); it != NULL;
             it = rawstor_string_list_next(it)) {
            char uuid[64];
            char version[64];
            rawstor_cli_target_ids(
                *it, uuid, sizeof(uuid), version, sizeof(version)
            );
            char location_buf[1024];
            rawstor_cli_target_location(
                *it, location_buf, sizeof(location_buf)
            );
            RawstorCliCell cells[] = {
                rawstor_cli_cell_optional(uuid),
                rawstor_cli_cell_string(*it),
                rawstor_cli_cell_string(location_buf),
            };
            if (rawstor_cli_table_add_row(table, cells) < 0) {
                fprintf(stderr, "Out of memory\n");
                rawstor_string_list_delete(targets);
                rawstor_cli_op_destroy(&op);
                rawstor_cli_table_delete(table);
                return EXIT_FAILURE;
            }
        }
        rawstor_string_list_delete(targets);
    } while (!rawstor_pagination_token_empty(&token));

    rawstor_cli_op_destroy(&op);
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}
