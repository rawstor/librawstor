#ifndef RAWSTOR_CLI_REMOVE_H
#define RAWSTOR_CLI_REMOVE_H

#include <rawstor.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_cli_remove(
    const struct RawstorOpts *opts,
    const struct RawstorSocketAddress *default_ost,
    const struct RawstorUUID *object_id);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_CLI_DELETE_H
