#include "info.h"

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
static void rawstor_cli_info_progress(int tty, uint64_t count) {
    if (!tty) {
        return;
    }
    fprintf(
        stderr, "\r\x1b[Kscanning objects: %llu", (unsigned long long)count
    );
    fflush(stderr);
}

/* Erases whatever rawstor_cli_info_progress() left on the line -- call
 * before anything else touches stderr (an error message) or stdout (the
 * final report), or that output would run into the progress line. */
static void rawstor_cli_info_progress_clear(int tty) {
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
static void rawstor_cli_info_print(
    const char* location, uint64_t used, uint64_t total, char unit,
    int have_logical, uint64_t logical_used
) {
    uint64_t avail = total > used ? total - used : 0;

    char used_buf[256];
    char total_buf[256];
    char avail_buf[256];
    char logical_buf[256];
    if (unit == 0) {
        rawstd_bytes_to_size_human(used, used_buf, sizeof(used_buf));
        rawstd_bytes_to_size_human(avail, avail_buf, sizeof(avail_buf));
        rawstd_bytes_to_size_human(total, total_buf, sizeof(total_buf));
        if (have_logical) {
            rawstd_bytes_to_size_human(
                logical_used, logical_buf, sizeof(logical_buf)
            );
        }
    } else {
        rawstd_bytes_to_size_unit(used, unit, used_buf, sizeof(used_buf));
        rawstd_bytes_to_size_unit(avail, unit, avail_buf, sizeof(avail_buf));
        rawstd_bytes_to_size_unit(total, unit, total_buf, sizeof(total_buf));
        if (have_logical) {
            rawstd_bytes_to_size_unit(
                logical_used, unit, logical_buf, sizeof(logical_buf)
            );
        }
    }

    double percent = total > 0 ? (double)used / (double)total * 100.0 : 0.0;

    printf("location: %s\n", location);
    printf("used: %s\n", used_buf);
    if (have_logical) {
        printf("used (logical): %s\n", logical_buf);
    }
    printf("available: %s\n", avail_buf);
    printf("total: %s\n", total_buf);
    printf("use%%: %.1f%%\n", percent);
}

static int rawstor_cli_info_physical(const char* location, char unit) {
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

    rawstor_cli_info_print(location, info.used, info.total, unit, 0, 0);

    return EXIT_SUCCESS;
}

/* Sums every object's own declared size (one rawstor_target_spec() call per
 * target) instead of asking the backend for its actual physical usage --
 * see info.h's own doc comment for why the two can diverge. Reuses the
 * same op/queue across the whole list()+spec()+info() sequence, same as
 * rawstor_cli_list()'s own pagination loop. */
static int rawstor_cli_info_logical(const char* location, char unit) {
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
            op.queue, location, 0, &targets, &token, rawstor_cli_op_cb, &op
        );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result < 0) {
            rawstor_cli_info_progress_clear(tty);
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
                    rawstor_cli_info_progress(tty, ++count);
                    continue;
                }
                rawstor_cli_info_progress_clear(tty);
                fprintf(
                    stderr, "rawstor_target_spec() failed for %s: %s\n", *it,
                    strerror((int)-spec_result)
                );
                rawstor_string_list_delete(targets);
                rawstor_cli_op_destroy(&op);
                return rawstd_exitcode_for_errno((int)-spec_result);
            }
            logical_used += spec.size;
            rawstor_cli_info_progress(tty, ++count);
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
    rawstor_cli_info_progress_clear(tty);
    if (info_result < 0) {
        fprintf(
            stderr, "rawstor_location_info() failed: %s\n",
            strerror((int)-info_result)
        );
        return rawstd_exitcode_for_errno((int)-info_result);
    }

    rawstor_cli_info_print(
        location, info.used, info.total, unit, 1, logical_used
    );

    return EXIT_SUCCESS;
}

int rawstor_cli_info(const char* location, char unit, int logical) {
    if (logical) {
        return rawstor_cli_info_logical(location, unit);
    }
    return rawstor_cli_info_physical(location, unit);
}
