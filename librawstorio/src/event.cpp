#include <rawstorio/event.hpp>

#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <memory>


namespace rawstor {
namespace io {


Event::Event(
    rawstor::io::Queue &q, std::unique_ptr<rawstor::io::Task> t):
    _q(q),
    _t(std::move(t))
#ifdef RAWSTOR_TRACE_EVENTS
    , _trace_id(rawstor_trace_event_begin(
        "Event(%d, %zu)\n", fd(), size()))
#endif
{}


Event::~Event() {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(
        _trace_id, "Event::~Event()\n");
#endif
}


void Event::dispatch() {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_message(_trace_id, "dispatch()\n");
    try {
#endif
        (*_t)(result(), error());
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


}} // rawstor::io
