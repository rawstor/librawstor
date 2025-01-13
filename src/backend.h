#ifndef _RAWSTOR_BACKEND_H_
#define _RAWSTOR_BACKEND_H_

#include "rawstor.h"

#include <sys/uio.h>

#include <stddef.h>


struct RawstorBackend {
    int (*volume_create)(struct RawstorDeviceSpec spec, int *device_id);

    int (*volume_delete)(int device_id);

    int (*volume_open)(int device_id, RawstorDevice **device);

    int (*volume_close)(RawstorDevice *device);

    int (*volume_spec)(int device_id, struct RawstorDeviceSpec *spec);

    int (*volume_readv)(
        RawstorDevice *device,
        size_t offset, size_t size,
        struct iovec *iov, unsigned int niov);

    int (*volume_writev)(
        RawstorDevice *device,
        size_t offset, size_t size,
        const struct iovec *iov, unsigned int niov);
};


#endif // _RAWSTOR_BACKEND_H_