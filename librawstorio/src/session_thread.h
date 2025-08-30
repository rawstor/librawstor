#ifndef RAWSTORIO_SESSION_THREAD_H
#define RAWSTORIO_SESSION_THREAD_H

#include "rawstorio/queue.h"


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOSession RawstorIOSession;


RawstorIOSession* rawstor_io_session_create(
    RawstorIOQueue *queue, int fd, int write);

void rawstor_io_session_delete(RawstorIOSession *session);

RawstorIOQueue* rawstor_io_session_queue(RawstorIOSession *session);

int rawstor_io_session_fd(RawstorIOSession *session);

int rawstor_io_session_write(RawstorIOSession *session);

int rawstor_io_session_push_sqe(
    RawstorIOSession *session, RawstorIOEvent *event);

int rawstor_io_session_kill(RawstorIOSession *session);

int rawstor_io_session_alive(RawstorIOSession *session);

int rawstor_io_session_compare(RawstorIOSession *session, int fd, int write);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_SESSION_THREAD_H
