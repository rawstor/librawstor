#ifndef RAWSTORIO_IO_SESSION_POLL_H
#define RAWSTORIO_IO_SESSION_POLL_H

#include <rawstor/io.h>

#include <rawstorio/io.h>

#include <rawstorstd/ringbuf.h>

#include <sys/uio.h>

#include <stddef.h>
#include <stdio.h>


typedef struct RawstorIOSession RawstorIOSession;


RawstorIOSession* rawstor_io_session_create(RawstorIO *io, int fd);

void rawstor_io_session_delete(RawstorIOSession *session);

int rawstor_io_session_fd(RawstorIOSession *session);

int rawstor_io_session_equal(RawstorIOSession *session, int fd);

short rawstor_io_session_poll_events(RawstorIOSession *session);

int rawstor_io_session_empty(RawstorIOSession *session);

int rawstor_io_session_read(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf);

int rawstor_io_session_pread(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf);

int rawstor_io_session_readv(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov);

int rawstor_io_session_preadv(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov);

int rawstor_io_session_write(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf);

int rawstor_io_session_pwrite(
    RawstorIOSession *session, RawstorIOEvent *event,
    void *buf);

int rawstor_io_session_writev(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov);

int rawstor_io_session_pwritev(
    RawstorIOSession *session, RawstorIOEvent *event,
    struct iovec *iov, unsigned int niov);

void rawstor_io_session_process_read(RawstorIOSession *session);

void rawstor_io_session_process_write(RawstorIOSession *session);

#endif // RAWSTORIO_IO_SESSION_POLL_H
