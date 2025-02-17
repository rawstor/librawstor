#ifndef RAWSTOR_AIO_H
#define RAWSTOR_AIO_H

#include <rawstor.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdio.h>


typedef struct RawstorAIO RawstorAIO;

// defined in rawstor.h
// typedef struct RawstorAIOEvent RawstorAIOEvent;

// defined in rawstor.h
// typedef int(*rawstor_aio_callback)(
//     RawstorAIOEvent *event, size_t size, ssize_t res, void *data);


extern const char* rawstor_aio_engine_name;

RawstorAIO* rawstor_aio_create(unsigned int depth);

void rawstor_aio_delete(RawstorAIO *aio);

/**
 * TODO: Do not support accept function in aio api.
 */
int rawstor_aio_accept(
    RawstorAIO *aio,
    int fd,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, void *buf, size_t size,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_readv(
    RawstorAIO *aio,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_pread(
    RawstorAIO *aio,
    int fd, void *buf, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_preadv(
    RawstorAIO *aio,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_recv(
    RawstorAIO *aio,
    int sock, void *buf, size_t size, int flags,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_recvmsg(
    RawstorAIO *aio,
    int sock, struct msghdr *message, size_t size, int flags,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, void *buf, size_t size,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_pwrite(
    RawstorAIO *aio,
    int fd, void *buf, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_writev(
    RawstorAIO *aio,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_pwritev(
    RawstorAIO *aio,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_send(
    RawstorAIO *aio,
    int sock, void *buf, size_t size, int flags,
    rawstor_aio_callback cb, void *data);

int rawstor_aio_sendmsg(
    RawstorAIO *aio,
    int sock, struct msghdr *message, size_t size, int flags,
    rawstor_aio_callback cb, void *data);


RawstorAIOEvent* rawstor_aio_wait_event(RawstorAIO *aio);

RawstorAIOEvent* rawstor_aio_wait_event_timeout(RawstorAIO *aio, int timeout);

void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event);

int rawstor_aio_event_fd(RawstorAIOEvent *event);

int rawstor_aio_event_dispatch(RawstorAIOEvent *event);

#endif // RAWSTOR_AIO_H
