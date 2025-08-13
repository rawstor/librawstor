#ifndef RAWSTORIO_IO_SESSION_UNSEEKABLE_THREAD_H
#define RAWSTORIO_IO_SESSION_UNSEEKABLE_THREAD_H

#include "io_session_thread.h"

#include <stddef.h>


typedef struct RawstorIOSessionUnseekable RawstorIOSessionUnseekable;


RawstorIOSessionUnseekable* rawstor_io_session_unseekable_create(
    RawstorIOSession *base);

void rawstor_io_session_unseekable_delete(RawstorIOSessionUnseekable *session);

int rawstor_io_session_unseekable_push_sqe(
    RawstorIOSessionUnseekable *session, RawstorIOEvent *event);


#endif // RAWSTORIO_IO_SESSION_UNSEEKABLE_THREAD_H
