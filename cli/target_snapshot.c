#include "target_snapshot.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>

int rawstor_cli_bind_snapshot_id(
    const char* target, const char* snapshot_id, char* buf, size_t size
) {
    char copy[65536];
    int n = snprintf(copy, sizeof(copy), "%s", target);
    if (n < 0 || (size_t)n >= sizeof(copy)) {
        return -ENAMETOOLONG;
    }

    buf[0] = '\0';
    char* saveptr = NULL;
    char* uri = strtok_r(copy, ",", &saveptr);
    while (uri != NULL) {
        size_t off = strlen(buf);
        int wn = snprintf(
            buf + off, size - off, "%s%s/%s", off == 0 ? "" : ",", uri,
            snapshot_id
        );
        if (wn < 0 || (size_t)wn >= size - off) {
            return -ENAMETOOLONG;
        }
        uri = strtok_r(NULL, ",", &saveptr);
    }
    return 0;
}
