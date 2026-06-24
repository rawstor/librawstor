#ifndef RAWSTOR_CLI_URI_H
#define RAWSTOR_CLI_URI_H

#include <rawstd/uuid.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_location_add_target(
    const char* location, const struct RawstdUUID* uuid, char* target,
    size_t size
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_URI_H
