#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_cli_create(const char *uri, size_t size);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_CLI_CREATE_H
