#ifndef RAWSTOR_CLI_REMOVE_H
#define RAWSTOR_CLI_REMOVE_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* `version` only words the messages: a target naming a version removes
 * that version, any other removes the live object. */
int rawstor_cli_remove(const char* target, int version);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_REMOVE_H
