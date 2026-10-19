#ifndef RAWSTOR_CLI_RESOLVE_H
#define RAWSTOR_CLI_RESOLVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Winners are member indices within each addressed chunk. A whole-object
 * target resolves every chunk; a physical URI resolves that chunk only. */
int rawstor_cli_resolve(
    const char* target, const size_t* winners, size_t num_winners
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_RESOLVE_H
