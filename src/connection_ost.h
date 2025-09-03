#ifndef RAWSTOR_CONNECTION_OST_H
#define RAWSTOR_CONNECTION_OST_H

#include <rawstor/rawstor.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorConnection RawstorConnection;


RawstorConnection* rawstor_connection_create(
    const struct RawstorSocketAddress *ost, size_t count);

void rawstor_connection_delete(RawstorConnection *cn);


#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CONNECTION_OST_H
