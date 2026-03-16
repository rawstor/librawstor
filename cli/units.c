#include "units.h"

#include <errno.h>
#include <stdio.h>

static int unit_to_shift(const char unit) {
    switch (unit) {
    case 'b':
    case 'B':
        return 0;
    case 'k':
    case 'K':
        return 10;
    case 'm':
    case 'M':
        return 20;
    case 'g':
    case 'G':
        return 30;
    case 't':
    case 'T':
        return 40;
    default:
        return -EINVAL;
    }
}

int rawstor_cli_size_to_bytes(const char* s, size_t* out) {
    size_t value;
    char unit;
    if (sscanf(s, "%zu%c", &value, &unit) != 2) {
        return -EINVAL;
    }

    int shift = unit_to_shift(unit);
    if (shift < 0) {
        return shift;
    }

    *out = value << shift;

    return 0;
}

int rawstor_cli_bytes_to_size(size_t value, char* buf, size_t size) {
    const char units[] = "BKMGT";
    size_t i;
    for (i = 0; i < sizeof(units) - 1; ++i) {
        if (value < 1024 || (value & 1023) != 0) {
            break;
        }
        value >>= 10;
    }
    return snprintf(buf, size, "%zu%c", value, units[i]);
}
