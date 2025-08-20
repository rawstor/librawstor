#include "io_event_poll.h"
#include <rawstorio/io_event.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <errno.h>
#include <unistd.h>



int rawstor_io_event_fd(RawstorIOEvent *event) {
    return rawstor_io_session_fd(event->session);
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
