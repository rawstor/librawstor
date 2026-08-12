#include "units.h"

#include <errno.h>
#include <stdint.h>
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
    case 'p':
    case 'P':
        return 50;
    case 'e':
    case 'E':
        return 60;
    default:
        return -EINVAL;
    }
}

int rawstor_cli_size_to_bytes(const char* s, uint64_t* out) {
    unsigned long long value;
    char unit;
    if (sscanf(s, "%llu%c", &value, &unit) != 2) {
        return -EINVAL;
    }

    int shift = unit_to_shift(unit);
    if (shift < 0) {
        return shift;
    }

    if (value > (UINT64_MAX >> shift)) {
        return -EOVERFLOW;
    }

    *out = value << shift;

    return 0;
}

static const char UNITS[] = "BKMGTPE";

int rawstor_cli_bytes_to_size(uint64_t value, char* buf, size_t size) {
    size_t i;
    for (i = 0; i < sizeof(UNITS) - 2; ++i) {
        if (value < 1024 || (value & 1023) != 0) {
            break;
        }
        value >>= 10;
    }
    return snprintf(
        buf, size, "%llu%c", (unsigned long long int)value, UNITS[i]
    );
}

static int bytes_to_size_shift(
    uint64_t value, int shift, char unit, char* buf, size_t size
) {
    uint64_t divisor = (uint64_t)1 << shift;
    uint64_t rounded = (value + divisor / 2) / divisor;
    const char* prefix = (value % divisor) != 0 ? "~" : "";
    return snprintf(
        buf, size, "%s%llu%c", prefix, (unsigned long long int)rounded, unit
    );
}

int rawstor_cli_bytes_to_size_human(uint64_t value, char* buf, size_t size) {
    size_t i = 0;
    uint64_t v = value;
    while (v >= 1024 && i < sizeof(UNITS) - 2) {
        v >>= 10;
        i++;
    }
    return bytes_to_size_shift(value, (int)i * 10, UNITS[i], buf, size);
}

int rawstor_cli_bytes_to_size_unit(
    uint64_t value, char unit, char* buf, size_t size
) {
    int shift = unit_to_shift(unit);
    if (shift < 0) {
        return shift;
    }
    return bytes_to_size_shift(value, shift, UNITS[shift / 10], buf, size);
}
