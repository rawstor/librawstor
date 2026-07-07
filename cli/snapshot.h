#ifndef RAWSTOR_CLI_SNAPSHOT_H
#define RAWSTOR_CLI_SNAPSHOT_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Creates a volume snapshot and prints its id to stdout. */
int rawstor_cli_snapshot(const char* target);

int rawstor_cli_snap_remove(const char* target, uint64_t snap_id);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_SNAPSHOT_H
