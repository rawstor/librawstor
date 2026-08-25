#include "info.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_info(const char* location, char unit) {
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
