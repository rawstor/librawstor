#include <rawstor.h>

#include "aio.h"
#include "logging.h"
#include "object.h"

#include <sys/socket.h>
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

    rawstor_info(
        "Rawstor compiled with IO engine: %s\n",
        rawstor_aio_engine_name);

    rawstor_info(
        "Rawstor compiled with object backend: %s\n",
        rawstor_object_backend_name);

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
    return rawstor_aio_event_dispatch(event);
}


void rawstor_release_event(RawstorAIOEvent *event) {
    rawstor_aio_release_event(rawstor_aio, event);
}


int rawstor_fd_accept(int fd, rawstor_aio_callback *cb, void *data) {
    return rawstor_aio_accept(rawstor_aio, fd, cb, data);
}


int rawstor_fd_read(
    int fd, void *buf, size_t size,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_read(
        rawstor_aio,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_pread(
        rawstor_aio,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_readv(
        rawstor_aio,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_preadv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_preadv(
        rawstor_aio,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_sock_recv(
    int sock, void *buf, size_t size, int flags,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_recv(
        rawstor_aio,
        sock, buf, size, flags,
        cb, data);
}


int rawstor_sock_recvmsg(
    int sock, struct msghdr *message, size_t size, int flags,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_recvmsg(
        rawstor_aio,
        sock, message, size, flags,
        cb, data);
}


int rawstor_fd_write(
    int fd, void *buf, size_t size,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_write(
        rawstor_aio,
        fd, buf, size,
        cb, data);
}


int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_pwrite(
        rawstor_aio,
        fd, buf, size, offset,
        cb, data);
}


int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_writev(
        rawstor_aio,
        fd, iov, niov, size,
        cb, data);
}


int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_pwritev(
        rawstor_aio,
        fd, iov, niov, size, offset,
        cb, data);
}


int rawstor_sock_send(
    int sock, void *buf, size_t size, int flags,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_send(
        rawstor_aio,
        sock, buf, size, flags,
        cb, data);
}


int rawstor_sock_sendmsg(
    int sock, struct msghdr *message, size_t size, int flags,
    rawstor_aio_callback *cb, void *data)
{
    return rawstor_aio_sendmsg(
        rawstor_aio,
        sock, message, size, flags,
        cb, data);
}
