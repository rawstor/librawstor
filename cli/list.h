#ifndef RAWSTOR_CLI_LIST_H
#define RAWSTOR_CLI_LIST_H

#include "output.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* `tenant` limits the listing to that tenant's objects; NULL takes the one
 * `location` names, and none lists every object. */
int rawstor_cli_list(
    const char* location, const char* tenant, const RawstorCliOutput* output
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_LIST_H
