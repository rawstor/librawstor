#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_create(
    const char* target, uint64_t size, uint64_t chunk_size, unsigned width
);

int rawstor_cli_create_at_vol(
    const char* location, const char* uuid, uint64_t size, uint64_t chunk_size,
    unsigned width
);

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_H
