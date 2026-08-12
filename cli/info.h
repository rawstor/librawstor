#ifndef RAWSTOR_CLI_INFO_H
#define RAWSTOR_CLI_INFO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * unit is 0 for a reasonable human-readable size (auto-picked, e.g. "141G"),
 * or one of "bBkKmMgGtTpPeE" to force a specific unit.
 */
int rawstor_cli_info(const char* location, char unit);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_INFO_H
