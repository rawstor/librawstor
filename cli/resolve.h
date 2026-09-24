#ifndef RAWSTOR_CLI_RESOLVE_H
#define RAWSTOR_CLI_RESOLVE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Each of winners[0..num_winners) is a mirror's own position within the
 * targeted chunk's own comma-separated order, same as `rawstor show -v`'s
 * own mirror[N] labels (nested under that chunk's own chunk[N]) -- more
 * than one when several members are declared jointly authoritative (e.g.
 * a manually-restored backup copied to more than one member) and
 * shouldn't resync from each other, only the rest. `has_offset` false
 * applies this to every chunk in the object (its own size/chunk_size,
 * via rawstor_target_spec(), say how many there are); true resolves only
 * the one chunk at `offset`. */
int rawstor_cli_resolve(
    const char* target, const size_t* winners, size_t num_winners,
    int has_offset, uint64_t offset
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_RESOLVE_H
