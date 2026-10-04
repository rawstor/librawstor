#include <rawstd/env.h>
#include <rawstd/logging.h>
#include <rawstd/units.h>

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>

int rawstd_env_uint(
    const char* name, unsigned int def, unsigned int min, unsigned int max,
    unsigned int* out
) {
    const char* value = getenv(name);
    if (value == NULL) {
        *out = def;
        return 0;
    }
    // Digits only: strtoull() would also skip whitespace and accept a sign.
    if (*value >= '0' && *value <= '9') {
        char* end;
        errno = 0;
        unsigned long long parsed = strtoull(value, &end, 10);
        if (errno == 0 && *end == '\0' && parsed >= min && parsed <= max) {
            *out = (unsigned int)parsed;
            return 0;
        }
    }
    rawstd_error(
        "Invalid %s=\"%s\": expected an integer from %u to %u\n", name, value,
        min, max
    );
    return -EINVAL;
}

int rawstd_env_bytes(
    const char* name, unsigned int def, unsigned int min, unsigned int max,
    unsigned int* out
) {
    const char* value = getenv(name);
    if (value == NULL) {
        *out = def;
        return 0;
    }
    uint64_t bytes;
    if (rawstd_size_to_bytes(value, &bytes) == 0 && bytes >= min &&
        bytes <= max) {
        *out = (unsigned int)bytes;
        return 0;
    }
    rawstd_error(
        "Invalid %s=\"%s\": expected a size with a unit (B, K, M, G, T, P, "
        "E) from %uB to %uB\n",
        name, value, min, max
    );
    return -EINVAL;
}
