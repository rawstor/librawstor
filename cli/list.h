#ifndef RAWSTOR_CLI_LIST_H
#define RAWSTOR_CLI_LIST_H

#include "output.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_list(const char* location, const RawstorCliOutput* output);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_LIST_H
