#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "rawstor.h"


/**
 * FIXME: Temporary workaround for rawstor_create() and rawstor_delete()
 * methods.
 */
static RawstorDeviceSpec _spec;
static RawstorDevice *_device = NULL;


int rawstor_create(RawstorDeviceSpec spec, int *device_id) {
    assert(_device == NULL);

    _spec = spec;
    _device = malloc(_spec.size);
    *device_id = 1;

    return 0;
}


int rawstor_delete(int device_id) {
    assert(device_id == 1);
    assert(_device != NULL);

    free(_device);
    _device = NULL;

    return 0;
}


int rawstor_open(int device_id, RawstorDevice **device) {
    assert(device_id == 1);
    assert(_device != NULL);

    *device = _device;

    return 0;
}


int rawstor_close(RawstorDevice *device) {
    assert(device != NULL);

    return 0;
}


int rawstor_spec(int device_id, RawstorDeviceSpec *spec) {
    assert(device_id == 1);
    assert(_device != NULL);

    *spec = _spec;

    return 0;
}


int rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf)
{
    memcpy(buf, device + offset, size);

    return 0;
}


int rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        rawstor_read(device, offset, chunk_size, iov[i].iov_base);

        size -= chunk_size;
        offset += chunk_size;
    }

    return 0;
}


int rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf)
{
    memcpy(device + offset, buf, size);

    return 0;
}


int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        rawstor_write(device, offset, chunk_size, iov[i].iov_base);

        size -= chunk_size;
        offset += chunk_size;
    }

    return 0;
}
