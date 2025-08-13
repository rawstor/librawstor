#ifndef RAWSTORIO_IO_SESSION_SEEKABLE_THREAD_H
#define RAWSTORIO_IO_SESSION_SEEKABLE_THREAD_H

#include "io_session_thread.h"

#include <stddef.h>


typedef struct RawstorIOSessionSeekable RawstorIOSessionSeekable;


RawstorIOSessionSeekable* rawstor_io_session_seekable_create(
    RawstorIOSession *base);

void rawstor_io_session_seekable_delete(RawstorIOSessionSeekable *session);

int rawstor_io_session_seekable_push_sqe(
    RawstorIOSessionSeekable *session, RawstorIOEvent *event);


#endif // RAWSTORIO_IO_SESSION_SEEKABLE_THREAD_H
