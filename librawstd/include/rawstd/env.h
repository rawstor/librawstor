#ifndef RAWSTD_ENV_H
#define RAWSTD_ENV_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Reads environment variable `name` into *out: `def` when it is unset,
 * otherwise a decimal integer from `min` to `max`. Anything else -- empty,
 * malformed or out of range -- is logged with the variable's name and
 * fails with -EINVAL, leaving *out untouched. Needs
 * rawstd_logging_initialize().
 */
int rawstd_env_uint(
    const char* name, unsigned int def, unsigned int min, unsigned int max,
    unsigned int* out
);

/*
 * Same, for a size with a mandatory unit as rawstd_size_to_bytes() parses
 * it, e.g. 256M or 4096B; `min` and `max` are in bytes. A bare number is
 * malformed.
 */
int rawstd_env_bytes(
    const char* name, unsigned int def, unsigned int min, unsigned int max,
    unsigned int* out
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_ENV_H
