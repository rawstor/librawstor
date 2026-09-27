#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// chunk_size is object policy, meaningful only for a target string that
// already names more than one chunk (create-by-target with a
// hand-built, multi-offset TARGET) -- ignored (0 is a valid, if
// meaningless, value) for the ordinary single-chunk case, see
// Target::create()'s own doc comment in target.cpp.
int rawstor_cli_create(
    const char* target, uint64_t size, uint64_t chunk_size, unsigned int mirrors
);

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size, uint64_t chunk_size,
    unsigned int mirrors
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_H
