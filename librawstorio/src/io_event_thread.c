#include "io_event_thread.h"

#include <rawstorstd/logging.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <unistd.h>


ssize_t rawstor_io_event_process_readv(RawstorIOEvent *event) {
    ssize_t ret = readv(
        event->session->fd, event->iov_at, event->niov_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "readv(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


ssize_t rawstor_io_event_process_preadv(RawstorIOEvent *event) {
    ssize_t ret = preadv(
        event->session->fd, event->iov_at, event->niov_at, event->offset_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "preadv(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


ssize_t rawstor_io_event_process_writev(RawstorIOEvent *event) {
    ssize_t ret = writev(
        event->session->fd, event->iov_at, event->niov_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "writev(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


ssize_t rawstor_io_event_process_pwritev(RawstorIOEvent *event) {
    ssize_t ret = pwritev(
        event->session->fd, event->iov_at, event->niov_at, event->offset_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "pwritev(): rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}
