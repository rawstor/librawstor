#include "rawstor.h"

#include "backend.h"

#include <sys/uio.h>

#include <stddef.h>


static const struct RawstorBackend *backend = NULL;


void rawstor_init(const struct RawstorBackend *b) {
    backend = b;
}


int rawstor_create(struct RawstorDeviceSpec spec, int *device_id) {
    return backend->volume_create(spec, device_id);
}


int rawstor_delete(int device_id) {
    return backend->volume_delete(device_id);
}


int rawstor_open(int device_id, RawstorDevice **device) {
    return backend->volume_open(device_id, device);
}


int rawstor_close(RawstorDevice *device) {
    return backend->volume_close(device);
}


int rawstor_spec(int device_id, struct RawstorDeviceSpec *spec) {
    return backend->volume_spec(device_id, spec);
}


int rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf)
{
    struct iovec iov = {
        .iov_base = buf,
        .iov_len = size,
    };

    return rawstor_readv(device, offset, size, &iov, 1);
}


int rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    return backend->volume_readv(device, offset, size, iov, niov);
}


int rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf)
{
    const struct iovec iov = {
        .iov_base = (void*)buf,
        .iov_len = size,
    };

    return rawstor_writev(device, offset, size, &iov, 1);
}


int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    return backend->volume_writev(device, offset, size, iov, niov);
}
