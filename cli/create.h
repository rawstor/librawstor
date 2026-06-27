#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_create_by_target(const char* target, size_t size);

int rawstor_cli_create_by_location(
    const char* location, const char* uuid_string, size_t size
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_H
