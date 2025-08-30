#ifndef RAWSTORIO_SESSION_UNSEEKABLE_THREAD_H
#define RAWSTORIO_SESSION_UNSEEKABLE_THREAD_H

#include "session_thread.h"

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOSessionUnseekable RawstorIOSessionUnseekable;


RawstorIOSessionUnseekable* rawstor_io_session_unseekable_create(
    RawstorIOSession *base);

void rawstor_io_session_unseekable_delete(RawstorIOSessionUnseekable *session);

int rawstor_io_session_unseekable_push_sqe(
    RawstorIOSessionUnseekable *session, RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_SESSION_UNSEEKABLE_THREAD_H
