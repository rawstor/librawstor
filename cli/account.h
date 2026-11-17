#ifndef RAWSTOR_CLI_ACCOUNT_H
#define RAWSTOR_CLI_ACCOUNT_H

#include "output.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Registers an account in the MDS at `location`: `account` is a UUID, or NULL
 * for a new one. Prints the account's id (the `account_id` column). */
int rawstor_cli_account_create(
    const char* location, const char* account, const RawstorCliOutput* output
);

/* Removes an empty account from the MDS at `location`. */
int rawstor_cli_account_remove(const char* location, const char* account);

/* Makes `account` (a UUID) the owner of the object `target` names. */
int rawstor_cli_transfer(const char* target, const char* account);

/* Prints the accounts registered in the MDS at `location`, a row of
 * `account_id` each. */
int rawstor_cli_account_list(
    const char* location, const RawstorCliOutput* output
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_ACCOUNT_H
