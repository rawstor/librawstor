#ifndef RAWSTOR_CLI_RESIZE_H
#define RAWSTOR_CLI_RESIZE_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int rawstor_cli_resize(const char* target, uint64_t new_size);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_RESIZE_H
