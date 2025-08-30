#ifndef RAWSTORIO_SESSION_SEEKABLE_THREAD_H
#define RAWSTORIO_SESSION_SEEKABLE_THREAD_H

#include "session_thread.h"

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOSessionSeekable RawstorIOSessionSeekable;


RawstorIOSessionSeekable* rawstor_io_session_seekable_create(
    RawstorIOSession *base);

void rawstor_io_session_seekable_delete(RawstorIOSessionSeekable *session);

int rawstor_io_session_seekable_push_sqe(
    RawstorIOSessionSeekable *session, RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_SESSION_SEEKABLE_THREAD_H
