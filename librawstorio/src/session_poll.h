#ifndef RAWSTORIO_SESSION_POLL_H
#define RAWSTORIO_SESSION_POLL_H

#include <rawstorio/queue.h>

#include <rawstorstd/ringbuf.h>

#include <rawstor/io_queue.h>

#include <sys/uio.h>

#include <stddef.h>
#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOSession RawstorIOSession;


RawstorIOSession* rawstor_io_session_create(RawstorIOQueue *queue, int fd);

void rawstor_io_session_delete(RawstorIOSession *session);

int rawstor_io_session_fd(RawstorIOSession *session);

int rawstor_io_session_equal(RawstorIOSession *session, int fd);

short rawstor_io_session_poll_events(RawstorIOSession *session);

int rawstor_io_session_empty(RawstorIOSession *session);

int rawstor_io_session_push_read_sqe(
    RawstorIOSession *session, RawstorIOEvent *event);

int rawstor_io_session_push_write_sqe(
    RawstorIOSession *session, RawstorIOEvent *event);

int rawstor_io_session_process_read(RawstorIOSession *session);

int rawstor_io_session_process_write(RawstorIOSession *session);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_SESSION_POLL_H
