#ifndef RAWSTORIO_IO_SESSION_POLL_H
#define RAWSTORIO_IO_SESSION_POLL_H

#include <rawstor/io.h>

#include <rawstorstd/ringbuf.h>

#include <sys/uio.h>

#include <stddef.h>
#include <stdio.h>


typedef struct RawstorIOSession {
    int fd;
    RawstorRingBuf *read_events;
    RawstorRingBuf *write_events;
} RawstorIOSession;


RawstorIOSession* rawstor_io_session_create(int fd, int depth);

void rawstor_io_session_delete(RawstorIOSession *session);

int rawstor_io_session_fd(RawstorIOSession *session);

int rawstor_io_session_equal(RawstorIOSession *session, int fd);

short rawstor_io_session_poll_events(RawstorIOSession *session);

int rawstor_io_session_empty(RawstorIOSession *session);

RawstorIOEvent* rawstor_io_session_push_read_event(
    RawstorIOSession *session,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

RawstorIOEvent* rawstor_io_session_push_write_event(
    RawstorIOSession *session,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);


#endif // RAWSTORIO_IO_SESSION_POLL_H
