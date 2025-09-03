#ifndef RAWSTOR_CLI_TESTIO_H
#define RAWSTOR_CLI_TESTIO_H

#include <rawstor.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_cli_testio(
    const struct RawstorOpts *opts,
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    size_t block_size, unsigned int count, unsigned int io_depth,
    int vector_mode);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_CLI_TESTIO_H
