#ifndef RAWSTOR_CLI_TENANT_H
#define RAWSTOR_CLI_TENANT_H

#ifdef __cplusplus
extern "C" {
#endif

/* Registers a tenant in the MDS at `location`: `tenant` is a UUID, or NULL
 * for a new one. Prints the tenant's id. */
int rawstor_cli_tenant_create(const char* location, const char* tenant);

/* Removes an empty tenant from the MDS at `location`. */
int rawstor_cli_tenant_remove(const char* location, const char* tenant);

/* Prints the tenants registered in the MDS at `location`, one id per line. */
int rawstor_cli_tenant_list(const char* location);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_TENANT_H
