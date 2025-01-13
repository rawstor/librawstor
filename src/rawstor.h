#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <sys/uio.h>

#include <stddef.h>


struct RawstorBackend;

extern const struct RawstorBackend *rawstor_backend_mem;

typedef void RawstorDevice;

struct RawstorDeviceSpec {
    size_t size;
};


void rawstor_init(const struct RawstorBackend *backend);

int rawstor_create(struct RawstorDeviceSpec spec, int *device_id);

int rawstor_delete(int device_id);

int rawstor_open(int device_id, RawstorDevice **device);

int rawstor_close(RawstorDevice *device);

int rawstor_spec(int device_id, struct RawstorDeviceSpec *spec);

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
