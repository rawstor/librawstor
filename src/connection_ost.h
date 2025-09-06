#ifndef RAWSTOR_CONNECTION_OST_H
#define RAWSTOR_CONNECTION_OST_H

#include <rawstor/object.h>
#include <rawstor/rawstor.h>
#include <rawstor/uuid.h>

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorConnection RawstorConnection;


RawstorConnection* rawstor_connection_open(
    RawstorObject *object,
    const struct RawstorSocketAddress *ost,
    size_t count,
    unsigned int depth);

int rawstor_connection_close(RawstorConnection *cn);

int rawstor_connection_pread(
    RawstorConnection *cn,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_connection_preadv(
    RawstorConnection *cn,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_connection_pwrite(
    RawstorConnection *cn,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_connection_pwritev(
    RawstorConnection *cn,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);



#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CONNECTION_OST_H
