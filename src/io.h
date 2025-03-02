#ifndef RAWSTOR_IO_H
#define RAWSTOR_IO_H

#include <rawstor.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdio.h>


typedef struct RawstorIO RawstorIO;

// defined in rawstor.h
// typedef struct RawstorIOEvent RawstorIOEvent;

// defined in rawstor.h
// typedef int(RawstorIOCallback)(RawstorIOEvent *event, void *data);


extern const char* rawstor_io_engine_name;

RawstorIO* rawstor_io_create(unsigned int depth);

void rawstor_io_delete(RawstorIO *io);

int rawstor_io_read(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_readv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_pread(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_preadv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_recv(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_recvv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_write(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_pwrite(
    RawstorIO *io,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_writev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_pwritev(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_send(
    RawstorIO *io,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_sendv(
    RawstorIO *io,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);


RawstorIOEvent* rawstor_io_wait_event(RawstorIO *io);

RawstorIOEvent* rawstor_io_wait_event_timeout(RawstorIO *io, int timeout);

void rawstor_io_release_event(RawstorIO *io, RawstorIOEvent *event);

int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);

int rawstor_io_event_dispatch(RawstorIOEvent *event);

#endif // RAWSTOR_IO_H
