#include <rawstor.h>

#include "aio.h"

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>


#define QUEUE_DEPTH 256


static RawstorAIO *global_aio = NULL;


int rawstor_initialize(void) {
    assert(global_aio == NULL);

    global_aio = rawstor_aio_create(QUEUE_DEPTH);
    if (global_aio == NULL) {
        return -errno;
    };

    return 0;
}


void rawstor_terminate(void) {
    rawstor_aio_delete(global_aio); 
}


RawstorAIOEvent* rawstor_fd_accept(int fd) {
    return rawstor_aio_accept(global_aio, fd);
}


RawstorAIOEvent* rawstor_fd_read(
    int fd, size_t offset,
    void *buf, size_t size)
{
    return rawstor_aio_read(global_aio, fd, offset, buf, size);
}


RawstorAIOEvent* rawstor_fd_readv(
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov)
{
    return rawstor_aio_readv(global_aio, fd, offset, iov, niov);
}


RawstorAIOEvent* rawstor_fd_write(
    int fd, size_t offset,
    void *buf, size_t size)
{
    return rawstor_aio_write(global_aio, fd, offset, buf, size);
}


RawstorAIOEvent* rawstor_fd_writev(
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov)
{
    return rawstor_aio_writev(global_aio, fd, offset, iov, niov);
}


RawstorAIOEvent* rawstor_wait_event(void) {
    return rawstor_aio_wait_event(global_aio);
}


int rawstor_dispatch_event(RawstorAIOEvent *) {
    return 0;
}


void rawstor_release_event(RawstorAIOEvent *event) {
    rawstor_aio_release_event(global_aio, event);
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
