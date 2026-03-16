#ifndef RAWSTOR_CLI_UNITS_H
#define RAWSTOR_CLI_UNITS_H

#include <stddef.h>
#include <unistd.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_size_to_bytes(const char* s, size_t* out);

int rawstor_cli_bytes_to_size(size_t value, char* buf, size_t size);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_UNITS_H
