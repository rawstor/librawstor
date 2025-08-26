#ifndef RAWSTORIO_IO_EVENT_POLL_H
#define RAWSTORIO_IO_EVENT_POLL_H

#include "io_session_poll.h"

#include <rawstorstd/logging.h>

#include <rawstor/io.h>

#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


struct RawstorIOEvent {
    int fd;

    struct iovec *iov_origin;
    struct iovec *iov_at;
    unsigned int niov_at;
    off_t offset;
    ssize_t (*process)(RawstorIOEvent *event);

    size_t size;
    ssize_t result;
    int error;

    RawstorIOCallback *callback;
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


#endif // RAWSTORIO_IO_EVENT_POLL_H
