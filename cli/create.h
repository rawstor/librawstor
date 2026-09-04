#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_create(
    const char* target, uint64_t size, uint32_t mirror_count
);

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size, uint32_t mirror_count
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_H
