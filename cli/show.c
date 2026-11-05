#include "show.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_show(const char* target, const RawstorCliOutput* output) {
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
    static const char* const version_columns[] = {
        "object_id", "version_id", "target", "size", "mirrors"
    };
    static const enum RawstorCliColumnType version_types[] = {
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_SIZE,
        RAWSTOR_CLI_COLUMN_NUMBER
    };
    static const char* const live_columns[] = {
        "object_id", "target", "size", "mirrors"
    };
    static const enum RawstorCliColumnType live_types[] = {
        RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
        RAWSTOR_CLI_COLUMN_SIZE, RAWSTOR_CLI_COLUMN_NUMBER
    };

    RawstorCliTable* table =
        has_version
            ? rawstor_cli_record_create(
                  "object", version_columns, version_types, 5
              )
            : rawstor_cli_record_create("object", live_columns, live_types, 4);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
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

    int ret = EXIT_FAILURE;
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
    } else {
        ret = rawstor_cli_output_print(output, &table, 1);
    }
    rawstor_cli_table_delete(table);
    return ret;
}
