#ifndef RAWSTOR_CLI_SNAP_REMOVE_H
#define RAWSTOR_CLI_SNAP_REMOVE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_snap_remove(const char* target, uint64_t snap_id);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_SNAP_REMOVE_H
