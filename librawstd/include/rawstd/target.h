#ifndef RAWSTD_TARGET_H
#define RAWSTD_TARGET_H

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Resolves the command-line spelling of a target into a target string.
 *
 * A target may be given as:
 *   - a full TARGET (`ost://host:port/UUID`, a comma-separated list of
 *     them, ...), returned as is; consumes @p first only;
 *   - `LOCATION UUID`: @p first is a location and @p second an object id,
 *     the id is appended to every URI of the location; consumes both;
 *   - a bare `UUID`: the location is taken from the RAWSTOR_LOCATION
 *     environment variable; consumes @p first only.
 *
 * An object id is a UUID, optionally followed by `/VERSION_UUID` or
 * `/HEX_OFFSET`, exactly as it follows the location in a target.
 *
 * @param first     The first positional argument; not NULL.
 * @param second    The positional argument after @p first, or NULL.
 * @param consumed  Receives how many of the arguments (1 or 2) form the
 *                  target.
 * @return A malloc()ed target string, or NULL with errno set: ENOENT when
 *         a bare UUID is given and RAWSTOR_LOCATION is unset or empty,
 *         ENOMEM.
 */
char* rawstd_target_resolve(
    const char* first, const char* second, int* consumed
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_TARGET_H
