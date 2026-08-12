#ifndef RAWSTOR_CLI_UNITS_H
#define RAWSTOR_CLI_UNITS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_size_to_bytes(const char* s, uint64_t* out);

int rawstor_cli_bytes_to_size(uint64_t value, char* buf, size_t size);

/**
 * Format value rounded to the largest unit that keeps it under 1024, e.g.
 * "141G" instead of "147357440K". Prefixes the result with '~' when the
 * rounding wasn't exact.
 */
int rawstor_cli_bytes_to_size_human(uint64_t value, char* buf, size_t size);

/**
 * Format value rounded to the given unit (one of "bBkKmMgGtTpPeE").
 * Prefixes the result with '~' when the rounding wasn't exact.
 */
int rawstor_cli_bytes_to_size_unit(
    uint64_t value, char unit, char* buf, size_t size
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_UNITS_H
