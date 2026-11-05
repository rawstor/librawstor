#ifndef RAWSTOR_CLI_CHUNKS_H
#define RAWSTOR_CLI_CHUNKS_H

#include "output.h"

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* One row per chunk of `target`, in offset order. */
int rawstor_cli_chunks(const char* target, const RawstorCliOutput* output);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CHUNKS_H
