#ifndef RAWSTOR_CLI_TENANT_H
#define RAWSTOR_CLI_TENANT_H

#include "output.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Registers a tenant in the MDS at `location`: `tenant` is a UUID, or NULL
 * for a new one. Prints the tenant's id (the `tenant_id` column). */
int rawstor_cli_tenant_create(
    const char* location, const char* tenant, const RawstorCliOutput* output
);

/* Removes an empty tenant from the MDS at `location`. */
int rawstor_cli_tenant_remove(const char* location, const char* tenant);

/* Makes `tenant` (a UUID) the owner of the object `target` names. */
int rawstor_cli_transfer(const char* target, const char* tenant);

/* Prints the tenants registered in the MDS at `location`, a row of
 * `tenant_id` each. */
int rawstor_cli_tenant_list(
    const char* location, const RawstorCliOutput* output
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_TENANT_H
