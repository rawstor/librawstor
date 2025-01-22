#include <rawstor.h>

#include <sys/uio.h>

#include <assert.h>
#include <stdlib.h>
#include <string.h>


typedef struct RawstorDevice {
    void *data;
} RawstorDevice;


/**
 * FIXME: Temporary workaround for volume_create() and volume_delete() methods.
 */
static struct RawstorDeviceSpec _spec;
static RawstorDevice _device;


int rawstor_create(struct RawstorDeviceSpec spec, int *device_id) {
    _spec = spec;
    _device.data = malloc(_spec.size);
    *device_id = 1;

    return 0;
}


int rawstor_delete(int device_id) {
    assert(device_id == 1);

    free(_device.data);

    return 0;
}


int rawstor_open(int device_id, RawstorDevice **device) {
    assert(device_id == 1);

    *device = &_device;

    return 0;
}


int rawstor_close(RawstorDevice *) {
    return 0;
}


int rawstor_spec(int device_id, struct RawstorDeviceSpec *spec) {
    assert(device_id == 1);

    *spec = _spec;

    return 0;
}


int rawstor_readv(
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


int rawstor_writev(
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
