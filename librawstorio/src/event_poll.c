#include "event_poll.h"
#include <rawstorio/event.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <unistd.h>



int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd;
}


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->result;
}


int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->error;
}


ssize_t rawstor_io_event_process_readv(RawstorIOEvent *event) {
    ssize_t ret = readv(
        event->fd, event->iov_at, event->niov_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "readv() rval = %zd\n", ret);
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
        event->fd, event->iov_at, event->niov_at, event->offset);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "preadv() rval = %zd\n", ret);
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
        event->fd, event->iov_at, event->niov_at);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "writev() rval = %zd\n", ret);
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
        event->fd, event->iov_at, event->niov_at, event->offset);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "pwritev() rval = %zd\n", ret);
#endif
    if (ret < 0) {
        event->error = errno;
    } else {
        event->result += ret;
    }
    return ret;
}


int rawstor_io_event_dispatch(RawstorIOEvent *event) {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(event->trace_event, "dispatch()\n");
#endif
    int ret = event->callback(event, event->data);
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(
        event->trace_event, "dispatch(): rval = %d\n", ret);
#endif
    return ret;
}
