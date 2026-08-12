#include "info.h"

#include "units.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_info(const char* location, char unit) {
    struct RawstorLocationInfo info;
    int res = rawstor_location_info(location, &info);
    if (res) {
        fprintf(stderr, "rawstor_location_info() failed: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    uint64_t avail = info.total > info.used ? info.total - info.used : 0;

    char used_buf[256];
    char total_buf[256];
    char avail_buf[256];
    if (unit == 0) {
        rawstor_cli_bytes_to_size_human(info.used, used_buf, sizeof(used_buf));
        rawstor_cli_bytes_to_size_human(avail, avail_buf, sizeof(avail_buf));
        rawstor_cli_bytes_to_size_human(
            info.total, total_buf, sizeof(total_buf)
        );
    } else {
        rawstor_cli_bytes_to_size_unit(
            info.used, unit, used_buf, sizeof(used_buf)
        );
        rawstor_cli_bytes_to_size_unit(
            avail, unit, avail_buf, sizeof(avail_buf)
        );
        rawstor_cli_bytes_to_size_unit(
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
