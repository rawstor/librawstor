#ifndef RAWSTOR_CLI_RESOLVE_H
#define RAWSTOR_CLI_RESOLVE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Each of winners[0..num_winners) is a position in target's own
 * comma-separated order, same as `rawstor show -v`'s own mirror[N]
 * labels -- more than one when several members are declared jointly
 * authoritative (e.g. a manually-restored backup copied to more than one
 * member) and shouldn't resync from each other, only the rest. */
int rawstor_cli_resolve(
    const char* target, const size_t* winners, size_t num_winners
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_RESOLVE_H
