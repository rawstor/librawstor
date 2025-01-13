#include "backend.h"

#include "rawstor.h"

#include <sys/uio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>


/**
 * FIXME: Temporary workaround for volume_create() and volume_delete() methods.
 */
static struct RawstorDeviceSpec _spec;
static RawstorDevice *_device = NULL;


static int volume_create(struct RawstorDeviceSpec spec, int *device_id) {
    assert(_device == NULL);

    _spec = spec;
    _device = malloc(_spec.size);
    *device_id = 1;

    return 0;
}


static int volume_delete(int device_id) {
    assert(device_id == 1);
    assert(_device != NULL);

    free(_device);
    _device = NULL;

    return 0;
}


int volume_open(int device_id, RawstorDevice **device) {
    assert(device_id == 1);
    assert(_device != NULL);

    *device = _device;

    return 0;
}


int volume_close(RawstorDevice *device) {
    assert(device != NULL);

    return 0;
}


int volume_spec(int device_id, struct RawstorDeviceSpec *spec) {
    assert(device_id == 1);
    assert(_device != NULL);

    *spec = _spec;

    return 0;
}


int volume_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        memcpy(iov[i].iov_base, device + offset, chunk_size);

        size -= chunk_size;
        offset += chunk_size;
    }

    return 0;
}


static int volume_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        memcpy(device + offset, iov[i].iov_base, chunk_size);

        size -= chunk_size;
        offset += chunk_size;
    }

    return 0;
}


static struct RawstorBackend backend = {
    .volume_create = volume_create,
    .volume_delete = volume_delete,
    .volume_open = volume_open,
    .volume_close = volume_close,
    .volume_spec = volume_spec,
    .volume_readv = volume_readv,
    .volume_writev = volume_writev,
};


const struct RawstorBackend *rawstor_backend_mem = &backend;
