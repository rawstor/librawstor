#include <rawstor.h>

#include "aio.h"

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>


#define QUEUE_DEPTH 256


static RawstorAIO *global_aio = NULL;


int rawstor_initialize() {
    assert(global_aio == NULL);

    global_aio = rawstor_aio_create(QUEUE_DEPTH);
    if (global_aio == NULL) {
        return -errno;
    };

    return 0;
}


void rawstor_terminate() {
    rawstor_aio_delete(global_aio); 
}


RawstorAIO* rawstor_aio() {
    return global_aio;
}


RawstorAIOEvent* rawstor_get_event() {
    return rawstor_aio_get_event(global_aio);
}

int rawstor_dispatch_event(RawstorAIOEvent *event) {
    return rawstor_aio_dispatch_event(global_aio, event);
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
