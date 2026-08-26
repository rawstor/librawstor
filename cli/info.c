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

    uint64_t avail = info.total > info.used ? info.total - info.used : 0;

    char used_buf[256];
    char total_buf[256];
    char avail_buf[256];
    if (unit == 0) {
        rawstd_bytes_to_size_human(info.used, used_buf, sizeof(used_buf));
        rawstd_bytes_to_size_human(avail, avail_buf, sizeof(avail_buf));
        rawstd_bytes_to_size_human(info.total, total_buf, sizeof(total_buf));
    } else {
        rawstd_bytes_to_size_unit(info.used, unit, used_buf, sizeof(used_buf));
        rawstd_bytes_to_size_unit(avail, unit, avail_buf, sizeof(avail_buf));
        rawstd_bytes_to_size_unit(
            info.total, unit, total_buf, sizeof(total_buf)
        );
    }

    double percent =
        info.total > 0 ? (double)info.used / (double)info.total * 100.0 : 0.0;

    printf("location: %s\n", location);
    printf("used: %s\n", used_buf);
    printf("available: %s\n", avail_buf);
    printf("total: %s\n", total_buf);
    printf("use%%: %.1f%%\n", percent);

    return EXIT_SUCCESS;
}

/* Sums every object's own declared size (one rawstor_target_spec() call per
 * target) instead of asking the backend for its actual physical usage --
 * see info.h's own doc comment for why the two can diverge. Reuses the
 * same op/queue across the whole list()+spec() sequence, same as
 * rawstor_cli_list()'s own pagination loop. */
static int rawstor_cli_info_logical(const char* location, char unit) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    uint64_t used = 0;
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
                    continue;
                }
                fprintf(
                    stderr, "rawstor_target_spec() failed for %s: %s\n", *it,
                    strerror((int)-spec_result)
                );
                rawstor_string_list_delete(targets);
                rawstor_cli_op_destroy(&op);
                return rawstd_exitcode_for_errno((int)-spec_result);
            }
            used += spec.size;
        }
        rawstor_string_list_delete(targets);
    } while (!rawstor_pagination_token_empty(&token));

    rawstor_cli_op_destroy(&op);

    char used_buf[256];
    if (unit == 0) {
        rawstd_bytes_to_size_human(used, used_buf, sizeof(used_buf));
    } else {
        rawstd_bytes_to_size_unit(used, unit, used_buf, sizeof(used_buf));
    }

    printf("location: %s\n", location);
    printf("used: %s\n", used_buf);

    return EXIT_SUCCESS;
}

int rawstor_cli_info(const char* location, char unit, int logical) {
    if (logical) {
        return rawstor_cli_info_logical(location, unit);
    }
    return rawstor_cli_info_physical(location, unit);
}
