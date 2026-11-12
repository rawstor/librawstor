#include "info.h"

#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <errno.h>
#include <unistd.h>

/* In-place, single-line "N objects scanned so far" progress for the
 * list()+spec() loop below -- only when stderr is a terminal, so piped/
 * logged output stays clean. \x1b[K (clear to end of line) means each
 * update doesn't need to know how long the previous one was. */
static void info_progress(int tty, uint64_t count) {
    if (!tty) {
        return;
    }
    fprintf(
        stderr, "\r\x1b[Kscanning objects: %llu", (unsigned long long)count
    );
    fflush(stderr);
}

/* Erases whatever info_progress() left on the line -- call
 * before anything else touches stderr (an error message) or stdout (the
 * final report), or that output would run into the progress line. */
static void info_progress_clear(int tty) {
    if (!tty) {
        return;
    }
    fprintf(stderr, "\r\x1b[K");
    fflush(stderr);
}

/* Shared by both info_physical/info_logical below. used/available/total/
 * use% always come from the location's actual physical capacity; when
 * have_logical is set, an extra "used (logical)" line (the sum of every
 * object's own declared size -- see info.h's own doc comment) is printed
 * right after "used", additional to it rather than replacing it. */
static int info_print(
    const char* location, uint64_t used, uint64_t total, int have_logical,
    uint64_t logical_used, const RawstorCliOutput* output
) {
    uint64_t avail = total > used ? total - used : 0;

    double percent = total > 0 ? (double)used / (double)total * 100.0 : 0.0;

    char percent_buf[32];
    snprintf(percent_buf, sizeof(percent_buf), "%.1f%%", percent);

    RawstorCliCell location_cell = rawstor_cli_cell_string(location);
    RawstorCliCell used_cell = rawstor_cli_cell_size(used);
    RawstorCliCell logical_cell = rawstor_cli_cell_size(logical_used);
    RawstorCliCell avail_cell = rawstor_cli_cell_size(avail);
    RawstorCliCell total_cell = rawstor_cli_cell_size(total);
    RawstorCliCell percent_cell = rawstor_cli_cell_string(percent_buf);

    /* "used_logical" is a column only when it was computed. */
    RawstorCliTable* table;
    RawstorCliCell cells[6];
    if (have_logical) {
        static const char* const columns[] = {
            "location",  "used",  "used_logical",
            "available", "total", "use_percent",
        };
        static const enum RawstorCliColumnType types[] = {
            RAWSTOR_CLI_COLUMN_STRING,     RAWSTOR_CLI_COLUMN_SIZE_HUMAN,
            RAWSTOR_CLI_COLUMN_SIZE_HUMAN, RAWSTOR_CLI_COLUMN_SIZE_HUMAN,
            RAWSTOR_CLI_COLUMN_SIZE_HUMAN, RAWSTOR_CLI_COLUMN_STRING,
        };
        table = rawstor_cli_record_create("info", columns, types, 6);
        cells[0] = location_cell;
        cells[1] = used_cell;
        cells[2] = logical_cell;
        cells[3] = avail_cell;
        cells[4] = total_cell;
        cells[5] = percent_cell;
    } else {
        static const char* const columns[] = {
            "location", "used", "available", "total", "use_percent",
        };
        static const enum RawstorCliColumnType types[] = {
            RAWSTOR_CLI_COLUMN_STRING,     RAWSTOR_CLI_COLUMN_SIZE_HUMAN,
            RAWSTOR_CLI_COLUMN_SIZE_HUMAN, RAWSTOR_CLI_COLUMN_SIZE_HUMAN,
            RAWSTOR_CLI_COLUMN_STRING,
        };
        table = rawstor_cli_record_create("info", columns, types, 5);
        cells[0] = location_cell;
        cells[1] = used_cell;
        cells[2] = avail_cell;
        cells[3] = total_cell;
        cells[4] = percent_cell;
    }
    if (table == NULL || rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
        if (table != NULL) {
            rawstor_cli_table_delete(table);
        }
        return EXIT_FAILURE;
    }
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}

static int info_physical(const char* location, const RawstorCliOutput* output) {
    struct RawstorLocationInfo info;

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_location_info(
        op.queue, location, &info, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_info() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    return info_print(location, info.used, info.total, 0, 0, output);
}

/* Sums every object's own declared size (one rawstor_target_spec() call per
 * target) instead of asking the backend for its actual physical usage --
 * see info.h's own doc comment for why the two can diverge. Reuses the
 * same op/queue across the whole list()+spec()+info() sequence, same as
 * rawstor_cli_list()'s own pagination loop. */
static int info_logical(const char* location, const RawstorCliOutput* output) {
    int tty = isatty(STDERR_FILENO);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    uint64_t logical_used = 0;
    uint64_t count = 0;
    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    do {
        op.done = 0;
        int sres = rawstor_location_list(
            op.queue, location, 0, &targets, NULL, &token, rawstor_cli_op_cb,
            &op
        );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result < 0) {
            info_progress_clear(tty);
            fprintf(
                stderr, "rawstor_location_list() failed: %s\n",
                strerror((int)-result)
            );
            rawstor_cli_op_destroy(&op);
            return rawstd_exitcode_for_errno((int)-result);
        }

        for (const char** it = rawstor_string_list_iter(targets); it != NULL;
             it = rawstor_string_list_next(it)) {
            struct RawstorObjectSpec spec;
            op.done = 0;
            int spec_sres = rawstor_target_spec(
                op.queue, *it, &spec, rawstor_cli_op_cb, &op
            );
            ssize_t spec_result = rawstor_cli_op_wait(&op, spec_sres);
            if (spec_result < 0) {
                /* Removed between list() and this spec() call -- expected
                 * under concurrent use, not a real failure. Just excludes
                 * it from the sum rather than aborting the whole count. */
                if ((int)-spec_result == ENOENT) {
                    info_progress(tty, ++count);
                    continue;
                }
                info_progress_clear(tty);
                fprintf(
                    stderr, "rawstor_target_spec() failed for %s: %s\n", *it,
                    strerror((int)-spec_result)
                );
                rawstor_string_list_delete(targets);
                rawstor_cli_op_destroy(&op);
                return rawstd_exitcode_for_errno((int)-spec_result);
            }
            logical_used += spec.size;
            info_progress(tty, ++count);
        }
        rawstor_string_list_delete(targets);
    } while (!rawstor_pagination_token_empty(&token));

    struct RawstorLocationInfo info;
    op.done = 0;
    int info_sres = rawstor_location_info(
        op.queue, location, &info, rawstor_cli_op_cb, &op
    );
    ssize_t info_result = rawstor_cli_op_wait(&op, info_sres);
    rawstor_cli_op_destroy(&op);
    info_progress_clear(tty);
    if (info_result < 0) {
        fprintf(
            stderr, "rawstor_location_info() failed: %s\n",
            strerror((int)-info_result)
        );
        return rawstd_exitcode_for_errno((int)-info_result);
    }

    return info_print(location, info.used, info.total, 1, logical_used, output);
}

int rawstor_cli_info(
    const char* location, int logical, const RawstorCliOutput* output
) {
    if (logical) {
        return info_logical(location, output);
    }
    return info_physical(location, output);
}
