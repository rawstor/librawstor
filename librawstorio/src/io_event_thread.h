#ifndef RAWSTORIO_IO_EVENT_THREAD_H
#define RAWSTORIO_IO_EVENT_THREAD_H

#include "io_session_thread.h"

#include <rawstorstd/logging.h>

#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


struct RawstorIOEvent {
    RawstorIOSession *session;

    int fd;
    struct iovec *iov_origin;
    struct iovec *iov_at;
    unsigned int niov_at;
    off_t offset_at;
    ssize_t (*process)(RawstorIOEvent *event);

    RawstorIOCallback *callback;

    size_t size;
    ssize_t result;
    int error;

    void *data;

#ifdef RAWSTOR_TRACE_EVENTS
    void *trace_event;
#endif
};


ssize_t rawstor_io_event_process_readv(RawstorIOEvent *event);

ssize_t rawstor_io_event_process_preadv(RawstorIOEvent *event);

ssize_t rawstor_io_event_process_writev(RawstorIOEvent *event);

ssize_t rawstor_io_event_process_pwritev(RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_IO_EVENT_THREAD_H
