#ifndef RAWSTOR_CLI_INFO_H
#define RAWSTOR_CLI_INFO_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * unit is 0 for a reasonable human-readable size (auto-picked, e.g. "141G"),
 * or one of "bBkKmMgGtTpPeE" to force a specific unit.
 *
 * logical, if nonzero, prints an extra "used (logical)" line -- the sum of
 * every object's own declared size (RawstorObjectSpec::size, one
 * rawstor_target_spec() call per object) -- in addition to (not instead
 * of) the usual "used", which stays the location's actual physical usage.
 * The two can diverge -- e.g. a sparse file:// object that's never been
 * fully written, or an object whose backing store reports usage in whole
 * blocks -- even though they happen to coincide today. available/total/
 * use% are unaffected either way: derived from physical "used", same as
 * without this flag.
 */
int rawstor_cli_info(const char* location, char unit, int logical);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_INFO_H
