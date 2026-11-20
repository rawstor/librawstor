#ifndef RAWSTOR_CLI_LOCATIONS_H
#define RAWSTOR_CLI_LOCATIONS_H

#include "output.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Prints the locations of the topology of the MDS at `location`, a row of
 * `location` each. */
int rawstor_cli_location_list(
    const char* location, const RawstorCliOutput* output
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_LOCATIONS_H
