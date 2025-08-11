#ifndef RAWSTORIO_IO_SESSION_THREAD_H
#define RAWSTORIO_IO_SESSION_THREAD_H

#include "rawstorio/io.h"


typedef struct RawstorIOSession RawstorIOSession;


RawstorIOSession* rawstor_io_session_create(
    RawstorIO *io, size_t depth, int fd, int write);

void rawstor_io_session_delete(RawstorIOSession *session);

int rawstor_io_session_push_sqe(
    RawstorIOSession *session, RawstorIOEvent *event);

int rawstor_io_session_alive(RawstorIOSession *session);

int rawstor_io_session_compare(RawstorIOSession *session, int fd, int write);


#endif // RAWSTORIO_IO_SESSION_THREAD_H
