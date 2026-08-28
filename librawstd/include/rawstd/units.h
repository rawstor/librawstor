#ifndef RAWSTD_UNITS_H
#define RAWSTD_UNITS_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Parses a size like "256M" (a decimal number followed by one of
 * "bBkKmMgGtTpPeE", binary/1024-based) into bytes.
 */
int rawstd_size_to_bytes(const char* s, uint64_t* out);

int rawstd_bytes_to_size(uint64_t value, char* buf, size_t size);

/**
 * Format value rounded to the largest unit that keeps it under 1024, e.g.
 * "141G" instead of "147357440K". Prefixes the result with '~' when the
 * rounding wasn't exact.
 */
int rawstd_bytes_to_size_human(uint64_t value, char* buf, size_t size);

/**
 * Format value rounded to the given unit (one of "bBkKmMgGtTpPeE").
 * Prefixes the result with '~' when the rounding wasn't exact.
 */
int rawstd_bytes_to_size_unit(
    uint64_t value, char unit, char* buf, size_t size
);

/**
 * Format value with a "'" every 3 digits (e.g. 1000000 -> "1'000'000"), for
 * readability in printed output. Locale-independent -- always "'", never a
 * locale's own thousands separator.
 */
int rawstd_uint64_grouped(uint64_t value, char* buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_UNITS_H
