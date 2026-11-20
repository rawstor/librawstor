#ifndef RAWSTOR_CLI_LIST_H
#define RAWSTOR_CLI_LIST_H

#include "output.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* The account `location` names limits the listing to its objects; without one
 * every object is listed. `held_by`, the location URI of an entry of the
 * topology of the MDS at `location`, limits it to the objects that have a slot
 * or a version member there; NULL for no limit. */
int rawstor_cli_list(
    const char* location, const char* held_by, const RawstorCliOutput* output
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_LIST_H
