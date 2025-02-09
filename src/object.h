#ifndef RAWSTOR_OBJECT_H
#define RAWSTOR_OBJECT_H

#include <rawstor.h>

#include <sys/uio.h>

#include <stddef.h>


extern const char *rawstor_object_backend_name;


int rawstor_object_create(struct RawstorObjectSpec spec, int *object_id);

int rawstor_object_delete(int object_id);

int rawstor_object_open(int object_id, RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(int object_id, struct RawstorObjectSpec *spec);

int rawstor_object_read(
    RawstorObject *object, off_t offset,
    void *buf, size_t size,
    rawstor_callback cb, void *data);

int rawstor_object_readv(
    RawstorObject *object, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data);

int rawstor_object_write(
    RawstorObject *object, off_t offset,
    void *buf, size_t size,
    rawstor_callback cb, void *data);

int rawstor_object_writev(
    RawstorObject *object, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data);


#endif // RAWSTOR_OBJECT_H
