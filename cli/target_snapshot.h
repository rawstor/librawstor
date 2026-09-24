#ifndef RAWSTOR_CLI_TARGET_SNAPSHOT_H
#define RAWSTOR_CLI_TARGET_SNAPSHOT_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Appends "/<snapshot_id>" to every comma-separated URI in `target`,
 * writing the result into `buf` (size `size`) -- the bound-snapshot path
 * segment rawstor_target_create()/rawstor_target_remove() read back via
 * rawstor_target_snapshot_id(). Returns 0 on success, -ENAMETOOLONG if
 * `buf` is too small for the result. */
int rawstor_cli_bind_snapshot_id(
    const char* target, const char* snapshot_id, char* buf, size_t size
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_TARGET_SNAPSHOT_H
