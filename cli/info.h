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
 * logical, if nonzero, reports used as the sum of every object's own
 * declared size (RawstorObjectSpec::size, one rawstor_target_spec() call
 * per object) instead of the location's actual physical usage. The two
 * can diverge -- e.g. a sparse file:// object that's never been fully
 * written, or an object whose backing store reports usage in whole
 * blocks -- even though they happen to coincide today. total (and use%,
 * derived from it) still comes from the location's actual physical
 * capacity -- there's no such thing as location-wide logical capacity --
 * so use% then means how much of that capacity the declared sizes account
 * for; available has no meaningful logical counterpart and isn't shown.
 */
int rawstor_cli_info(const char* location, char unit, int logical);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_INFO_H
