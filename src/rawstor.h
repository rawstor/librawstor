#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <stddef.h>
#include <sys/uio.h>


typedef void RawstorDevice;

typedef struct {
    size_t size;
} RawstorDeviceSpec;


int rawstor_create(RawstorDeviceSpec spec, int *device_id);

int rawstor_delete(int device_id);

int rawstor_open(int device_id, RawstorDevice **device);

int rawstor_close(RawstorDevice *device);

int rawstor_spec(int device_id, RawstorDeviceSpec *spec);

int rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf);

int rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov);

int rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf);

int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov);


#endif // _RAWSTOR_H_
