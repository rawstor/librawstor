#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "rawstor.h"


/**
 * FIXME: Temporary workaround for rawstor_create() and rawstor_delete()
 * methods.
 */
static RawstorDeviceSpec _spec;
static RawstorDevice *_device = NULL;


int rawstor_create(RawstorDeviceSpec spec) {
    assert(_device == NULL);
    _spec = spec;
    _device = malloc(_spec.size);
    return 1;
}


void rawstor_delete(int device_id) {
    assert(device_id == 1);
    assert(_device != NULL);
    free(_device);
    _device = NULL;
}


RawstorDevice* rawstor_open(int device_id) {
    assert(device_id == 1);
    assert(_device != NULL);
    return _device;
}


void rawstor_close(RawstorDevice *device) {
    assert(device != NULL);
}


int rawstor_spec(int device_id, RawstorDeviceSpec *spec) {
    assert(device_id == 1);
    assert(_device != NULL);

    *spec = _spec;

    return 0;
}


void rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf)
{
    memcpy(buf, device + offset, size);
}


void rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    printf("rawstor_readv(%u)\n", niov);
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        rawstor_read(device, offset, chunk_size, iov[i].iov_base);

        size -= chunk_size;
        offset += chunk_size;
    }
}


void rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf)
{
    memcpy(device + offset, buf, size);
}


void rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    printf("rawstor_writev(%u)\n", niov);
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        rawstor_write(device, offset, chunk_size, iov[i].iov_base);

        size -= chunk_size;
        offset += chunk_size;
    }
}
