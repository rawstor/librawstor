#ifndef RAWSTORIO_EVENT_LIBURING_H
#define RAWSTORIO_EVENT_LIBURING_H

#include <rawstor/io_queue.h>

#include <rawstorstd/logging.h>

#include <liburing.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


struct RawstorIOEvent {
    int fd;

    RawstorIOCallback *callback;

    size_t size;
    struct io_uring_sqe *sqe;
    struct io_uring_cqe *cqe;

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


#endif // RAWSTORIO_EVENT_LIBURING_H
