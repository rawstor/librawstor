#ifndef RAWSTOR_CLI_SLOTS_H
#define RAWSTOR_CLI_SLOTS_H

#include "output.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One row per member slot of every chunk of `target`: where it lives and
 * everything its own record holds. */
int rawstor_cli_slots(const char* target, const RawstorCliOutput* output);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_SLOTS_H
