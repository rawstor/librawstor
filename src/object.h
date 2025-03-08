#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

#include <rawstor.h>

#include <sys/uio.h>

#include <stddef.h>


// defined in rawstor.h
// typedef struct RawstorObject RawstorObject;

// defined in rawstor.h
// struct RawstorObjectSpec {
//     size_t size;
// };

// defined in rawstor.h
// typedef int(RawstorCallback)(
//     RawstorObject *object, size_t size, size_t res, int error, void *data);


extern const char *rawstor_object_backend_name;

int rawstor_object_create(
    const struct RawstorObjectSpec *spec, int *object_id);

int rawstor_object_delete(int object_id);

int rawstor_object_open(int object_id, RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(int object_id, struct RawstorObjectSpec *spec);

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


#endif // RAWSTOR_OBJECT_H
