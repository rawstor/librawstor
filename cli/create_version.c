#include "create_version.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// One rawstor_target_create_version() attempt against a fresh queue,
// driven to completion synchronously -- returns its own result unchanged
// (the version target string's own length on success, negative errno on
// failure; rawstor_cli_op_init()'s own failure already comes back in that
// same shape, a negative errno).
static ssize_t try_create_version(
    const char* target, const char* uuid, char* version_target, size_t size
) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        return res;
    }

    int sres = rawstor_target_create_version(
        op.queue, target, uuid, version_target, size, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    return result;
}

int rawstor_cli_create_version(const char* target, const char* uuid) {
    fprintf(stderr, "Creating a version of: %s\n", target);

    /* `uuid` NULL: the version id is either already bound in `target`'s
     * own path, or generated fresh -- see rawstor_target_create_version(). */

    // NULL/0 asks for the version target string's own length alone --
    // the same snprintf(NULL, 0, ...) idiom rawstor_target_create_version()
    // itself just forwards to (target.cpp), needing no I/O and creating
    // nothing. The second call, into a buffer sized exactly for that
    // length, creates the real version.
    ssize_t result = try_create_version(target, uuid, NULL, 0);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create_version() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    char* version_target = malloc((size_t)result + 1);
    if (version_target == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    result =
        try_create_version(target, uuid, version_target, (size_t)result + 1);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create_version() failed: %s\n",
            strerror((int)-result)
        );
        free(version_target);
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Version created\n");
    fprintf(stdout, "%s\n", version_target);

    free(version_target);

    return EXIT_SUCCESS;
}

int rawstor_cli_list_versions(
    const char* target, const RawstorCliOutput* output
) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* versions = NULL;
    int sres = rawstor_target_versions(
        op.queue, target, &versions, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_versions() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    static const char* const columns[] = {"target"};
    static const enum RawstorCliColumnType types[] = {
        RAWSTOR_CLI_COLUMN_STRING
    };
    RawstorCliTable* table =
        rawstor_cli_table_create("versions", columns, types, 1);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        rawstor_string_list_delete(versions);
        return EXIT_FAILURE;
    }
    for (const char** it = rawstor_string_list_iter(versions); it != NULL;
         it = rawstor_string_list_next(it)) {
        RawstorCliCell cell = rawstor_cli_cell_string(*it);
        if (rawstor_cli_table_add_row(table, &cell) < 0) {
            fprintf(stderr, "Out of memory\n");
            rawstor_string_list_delete(versions);
            rawstor_cli_table_delete(table);
            return EXIT_FAILURE;
        }
    }
    rawstor_string_list_delete(versions);
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}
