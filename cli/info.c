#include "info.h"

#include "units.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_info(const char* location) {
    struct RawstorLocationInfo info;
    int res = rawstor_location_info(location, &info);
    if (res) {
        fprintf(stderr, "rawstor_location_info() failed: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    char used_buf[256];
    char total_buf[256];
    char avail_buf[256];
    rawstor_cli_bytes_to_size(info.used, used_buf, sizeof(used_buf));
    rawstor_cli_bytes_to_size(info.total, total_buf, sizeof(total_buf));
    uint64_t avail = info.total > info.used ? info.total - info.used : 0;
    rawstor_cli_bytes_to_size(avail, avail_buf, sizeof(avail_buf));

    double percent =
        info.total > 0 ? (double)info.used / (double)info.total * 100.0 : 0.0;

    printf("location: %s\n", location);
    printf("used: %s\n", used_buf);
    printf("available: %s\n", avail_buf);
    printf("total: %s\n", total_buf);
    printf("use%%: %.1f%%\n", percent);

    return EXIT_SUCCESS;
}
