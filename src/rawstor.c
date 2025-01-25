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


int rawstor_fd_accept(int fd, rawstor_aio_cb cb, void *data) {
    return rawstor_aio_accept(global_aio, fd, cb, data);
}


int rawstor_fd_read(
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_read(global_aio, fd, offset, buf, size, cb, data);
}


int rawstor_fd_readv(
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_readv(global_aio, fd, offset, iov, niov, cb, data);
}


int rawstor_fd_write(
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_write(global_aio, fd, offset, buf, size, cb, data);
}


int rawstor_fd_writev(
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data)
{
    return rawstor_aio_writev(global_aio, fd, offset, iov, niov, cb, data);
}


RawstorAIOEvent* rawstor_event_wait(void) {
    return rawstor_aio_event_wait(global_aio);
}


RawstorAIOEvent* rawstor_event_wait_timeout(int timeout) {
    return rawstor_aio_event_wait_timeout(global_aio, timeout);
}


int rawstor_event_dispatch(RawstorAIOEvent *event) {
    return rawstor_aio_event_cb(event);
}


void rawstor_event_release(RawstorAIOEvent *event) {
    rawstor_aio_event_release(global_aio, event);
}
