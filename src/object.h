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
// typedef int(*rawstor_callback)(
//     RawstorObject *object, size_t size, ssize_t res, void *data);


extern const char *rawstor_object_backend_name;

int rawstor_object_create(struct RawstorObjectSpec spec, int *object_id);

int rawstor_object_delete(int object_id);

int rawstor_object_open(int object_id, RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(int object_id, struct RawstorObjectSpec *spec);

int rawstor_object_read(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    rawstor_callback cb, void *data);

int rawstor_object_readv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_callback cb, void *data);

int rawstor_object_write(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    rawstor_callback cb, void *data);

int rawstor_object_writev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_callback cb, void *data);


#endif // RAWSTOR_OBJECT_H
