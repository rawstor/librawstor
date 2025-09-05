#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

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

struct RawstorObjectSpec {
    size_t size;
};

typedef int(RawstorCallback)(
    RawstorObject *object, size_t size, size_t res, int error, void *data);


int rawstor_object_create(
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id);

int rawstor_object_create_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id);

int rawstor_object_delete(const struct RawstorUUID *object_id);

int rawstor_object_delete_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id);

int rawstor_object_open(
    const struct RawstorUUID *object_id,
    RawstorObject **object);

int rawstor_object_open_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

const struct RawstorUUID* rawstor_object_get_id(RawstorObject *object);

int rawstor_object_spec(
    const struct RawstorUUID *object_id,
    struct RawstorObjectSpec *spec);

int rawstor_object_spec_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    struct RawstorObjectSpec *spec);

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


#endif // RAWSTOR_OBJECT_H
