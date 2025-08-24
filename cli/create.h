#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stddef.h>


int rawstor_cli_create(
    const struct RawstorOptsIO *opts_io,
    const struct RawstorOptsOST *opts_ost,
    size_t size);


#endif // RAWSTOR_CLI_CREATE_H
