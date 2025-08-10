#ifndef LIBRAWSTOR_OBJECT_H
#define LIBRAWSTOR_OBJECT_H

#include <rawstor/rawstor.h>
#include <rawstor/uuid.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorObject RawstorObject;

typedef struct {
    size_t size;
} RawstorObjectSpec;

typedef int(RawstorCallback)(
    RawstorObject *object, size_t size, size_t res, int error, void *data);


int rawstor_object_create(
    const RawstorOptsOST *opts_ost,
    const RawstorObjectSpec *spec,
    RawstorUUID *object_id);

int rawstor_object_delete(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id);

int rawstor_object_open(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id,
    RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id,
    RawstorObjectSpec *spec);

int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_pwritev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);


#ifdef __cplusplus
}
#endif


#endif // LIBRAWSTOR_OBJECT_H
