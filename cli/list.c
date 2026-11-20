#include "list.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const columns[] = {
    "object_id", "account", "target", "location"
};
static const enum RawstorCliColumnType types[] = {
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING
};

int rawstor_cli_list(
    const char* location, const char* held_by, const RawstorCliOutput* output
) {
    RawstorCliTable* table =
        rawstor_cli_table_create("targets", columns, types, 4);
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
        int sres = held_by == NULL
                       ? rawstor_location_list(
                             op.queue, location, 0, &targets, &token,
                             rawstor_cli_op_cb, &op
                         )
                       : rawstor_location_list_held(
                             op.queue, location, held_by, 0, &targets, &token,
                             rawstor_cli_op_cb, &op
                         );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result == -ENOENT && held_by != NULL) {
            /* What was typed may carry a password. */
            char shown[1024];
            rawstor_cli_uri_display(held_by, shown, sizeof(shown));
            fprintf(
                stderr,
                "%s is not a location of the topology (`rawstor location list "
                "MDS` prints them)\n",
                shown[0] != '\0' ? shown : "the location"
            );
            rawstor_cli_op_destroy(&op);
            rawstor_cli_table_delete(table);
            return rawstd_exitcode_for_errno(ENOENT);
        }
        if (result < 0) {
            fprintf(
                stderr, "%s() failed: %s\n",
                held_by == NULL ? "rawstor_location_list"
                                : "rawstor_location_list_held",
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
            char account[64];
            if (rawstor_target_account(*it, account, sizeof(account)) < 0) {
                account[0] = '\0';
            }
            char* target = rawstor_cli_list_target(*it, location);
            if (target == NULL) {
                fprintf(stderr, "Failed to format listed target\n");
                rawstor_string_list_delete(targets);
                rawstor_cli_op_destroy(&op);
                rawstor_cli_table_delete(table);
                return EXIT_FAILURE;
            }
            char location_buf[1024];
            rawstor_cli_target_location(
                target, location_buf, sizeof(location_buf)
            );
            RawstorCliCell cells[] = {
                rawstor_cli_cell_optional(uuid),
                rawstor_cli_cell_optional(account),
                rawstor_cli_cell_string(target),
                rawstor_cli_cell_string(location_buf),
            };
            int added = rawstor_cli_table_add_row(table, cells);
            free(target);
            if (added < 0) {
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
