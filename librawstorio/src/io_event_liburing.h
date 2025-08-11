#ifndef RAWSTORIO_IO_EVENT_LIBURING_H
#define RAWSTORIO_IO_EVENT_LIBURING_H

#include <rawstor/io.h>

#include <rawstorstd/logging.h>

#include <liburing.h>

#include <stddef.h>


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


#endif // RAWSTORIO_IO_EVENT_LIBURING_H
