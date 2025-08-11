#ifndef RAWSTORIO_IO_SESSION_THREAD_H
#define RAWSTORIO_IO_SESSION_THREAD_H

#include "rawstorio/io.h"

#include <rawstorstd/list.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/threading.h>


typedef struct RawstorIOSession {
    RawstorIO *io;
    int fd;
    int write;

    RawstorRingBuf *sqes;

    int exit;
    RawstorMutex *mutex;
    RawstorCond *cond;
    RawstorList *threads;
} RawstorIOSession;


RawstorIOSession* rawstor_io_session_create(
    RawstorIO *io, size_t depth, int fd, int write);

void rawstor_io_session_delete(RawstorIOSession *session);

int rawstor_io_session_push_sqe(
    RawstorIOSession *session, RawstorIOEvent *event);


#endif // RAWSTORIO_IO_SESSION_THREAD_H
