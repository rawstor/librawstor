#ifndef RAWSTOR_CONNECTION_OST_H
#define RAWSTOR_CONNECTION_OST_H

#include <rawstor/rawstor.h>
#include <rawstor/uuid.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorConnection RawstorConnection;


RawstorConnection* rawstor_connection_create(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    size_t count);

int rawstor_connection_delete(RawstorConnection *cn);


#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CONNECTION_OST_H
