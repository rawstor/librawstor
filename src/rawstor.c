#include <rawstor.h>

#include "aio.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>


#define QUEUE_DEPTH 256


static RawstorAIO *rawstor_aio = NULL;


int rawstor_initialize(void) {
    assert(rawstor_aio == NULL);

    rawstor_aio = rawstor_aio_create(QUEUE_DEPTH);
    if (rawstor_aio == NULL) {
        return -errno;
    };

    return 0;
}


void rawstor_terminate(void) {
    rawstor_aio_delete(rawstor_aio); 
}


RawstorAIOEvent* rawstor_wait_event(void) {
    return rawstor_aio_wait_event(rawstor_aio);
}


RawstorAIOEvent* rawstor_wait_event_timeout(int timeout) {
    return rawstor_aio_wait_event_timeout(rawstor_aio, timeout);
}


int rawstor_dispatch_event(RawstorAIOEvent *event) {
    return rawstor_aio_event_cb(event);
}


void rawstor_release_event(RawstorAIOEvent *event) {
    rawstor_aio_release_event(rawstor_aio, event);
}


int rawstor_fd_accept(int fd, rawstor_aio_cb cb, void *data) {
    return rawstor_aio_accept(rawstor_aio, fd, cb, data);
}


int rawstor_fd_read(
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_read(rawstor_aio, fd, offset, buf, size, cb, data);
}


int rawstor_fd_readv(
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_readv(rawstor_aio, fd, offset, iov, niov, cb, data);
}


int rawstor_fd_write(
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_write(rawstor_aio, fd, offset, buf, size, cb, data);
}


int rawstor_fd_writev(
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_writev(rawstor_aio, fd, offset, iov, niov, cb, data);
}
