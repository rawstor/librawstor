#include <rawstorio/event.hpp>

#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <memory>


RawstorIOEvent::RawstorIOEvent(
    rawstor::io::Queue &q, int fd, std::unique_ptr<rawstor::io::Task> t):
    _q(q),
    _fd(fd),
    _t(std::move(t))
#ifdef RAWSTOR_TRACE_EVENTS
    , _trace_id(rawstor_trace_event_begin(
        "RawstorIOEvent(%d, %zu)\n", fd, size()))
#endif
{}


RawstorIOEvent::~RawstorIOEvent() {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(
        _trace_id, "RawstorIOEvent::~RawstorIOEvent()\n");
#endif
}


void RawstorIOEvent::dispatch() {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(_trace_id, "dispatch()\n");
    try {
#endif
        (*_t)(this);
#ifdef RAWSTOR_TRACE_EVENTS
    } catch (std::exception &e) {
        rawstor_trace_event_message(
            _trace_id, "dispatch(): error: %s\n", e.what());
        throw;
    }
    rawstor_trace_event_message(
        _trace_id, "dispatch(): success\n");
#endif
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd();
}

size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size();
}

size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->result();
}

int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->error();
}
