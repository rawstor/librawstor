#include <rawstor.h>

#include "io.h"
#include "logging.h"
#include "object.h"

#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>


#define QUEUE_DEPTH 256


static RawstorIO *rawstor_io = NULL;


int rawstor_initialize(void) {
    assert(rawstor_io == NULL);

    rawstor_info(
        "Rawstor compiled with IO engine: %s\n",
        rawstor_io_engine_name);

    rawstor_info(
        "Rawstor compiled with object backend: %s\n",
        rawstor_object_backend_name);

    rawstor_io = rawstor_io_create(QUEUE_DEPTH);
    if (rawstor_io == NULL) {
        return -errno;
    };

    return 0;
}


void rawstor_terminate(void) {
    rawstor_io_delete(rawstor_io); 
}


RawstorIOEvent* rawstor_wait_event(void) {
    return rawstor_io_wait_event(rawstor_io);
}


RawstorIOEvent* rawstor_wait_event_timeout(int timeout) {
    return rawstor_io_wait_event_timeout(rawstor_io, timeout);
}


int rawstor_dispatch_event(RawstorIOEvent *event) {
    return rawstor_io_event_dispatch(event);
}


void rawstor_release_event(RawstorIOEvent *event) {
    rawstor_io_release_event(rawstor_io, event);
}


int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_read(
        rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_pread(
        rawstor_io,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_readv(
        rawstor_io,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_preadv(
        rawstor_io,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_fd_recv(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_recv(
        rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_recvv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_recvv(
        rawstor_io,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_write(
        rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_pwrite(
        rawstor_io,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_writev(
        rawstor_io,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_pwritev(
        rawstor_io,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_fd_send(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_send(
        rawstor_io,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_sendv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    return rawstor_io_sendv(
        rawstor_io,
        fd, iov, niov, size,
        cb, data);
}
