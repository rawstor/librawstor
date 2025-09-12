#include "event_liburing.h"
#include <rawstorio/event.h>

#include <rawstorstd/logging.h>

#include <stddef.h>


RawstorIOQueue* rawstor_io_event_queue(RawstorIOEvent *event) {
    return event->queue;
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd;
}


size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size;
}


size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->cqe->res >= 0 ? event->cqe->res : 0;
}


int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->cqe->res < 0 ? -event->cqe->res : 0;
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
