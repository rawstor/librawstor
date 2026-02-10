#include "rawstorstd/logging.h"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/threading.h>

#include <algorithm>
#include <vector>

#include <assert.h>
#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

RawstorMutex* rawstor_logging_mutex = NULL;

#ifdef RAWSTOR_TRACE_EVENTS

namespace {

typedef enum {
    EVENT_CREATING,
    EVENT_AVAILABLE,
    EVENT_MESSAGE,
    EVENT_DELETING,
    EVENT_DELETED,
} EventState;

class Event {
private:
    char _appearance;
    EventState _state;
    size_t _refs;

public:
    explicit Event(char appearance) :
        _appearance(appearance),
        _state(EVENT_CREATING),
        _refs(1) {}

    char appearance() const noexcept { return _appearance; }

    EventState state() const noexcept { return _state; }

    void deleting() noexcept { _state = EVENT_DELETING; }

    void message() noexcept { _state = EVENT_MESSAGE; }

    void available() noexcept { _state = EVENT_AVAILABLE; }

    void deleted() noexcept { _state = EVENT_DELETED; }

    size_t inc() noexcept { return ++_refs; }

    size_t dec() noexcept { return --_refs; }
};

std::vector<Event> events;

} // namespace

#endif // RAWSTOR_TRACE_EVENTS

int rawstor_logging_initialize() {
    rawstor_logging_mutex = rawstor_mutex_create();
    if (rawstor_logging_mutex == NULL) {
        int error = errno;
        errno = 0;
        return -error;
    }

    return 0;
}

void rawstor_logging_terminate(void) {
    rawstor_mutex_delete(rawstor_logging_mutex);
}

#ifdef RAWSTOR_TRACE_EVENTS

size_t rawstor_trace_event_va_begin(
    char appearance, const char* file, int line, const char* function,
    const char* format, va_list args
) {
    rawstor_mutex_lock(rawstor_logging_mutex);
    try {
        std::vector<Event>::iterator it =
            std::find_if(events.begin(), events.end(), [](const auto& event) {
                return event.state() == EVENT_DELETED;
            });

        if (it == events.end()) {
            events.push_back(Event(appearance));
            it = events.end() - 1;
        } else {
            *it = Event(appearance);
        }

        rawstor_trace_event_dump();

        dprintf(STDERR_FILENO, "TRACE %s:%d %s(): ", file, line, function);

        vdprintf(STDERR_FILENO, format, args);

        rawstor_mutex_unlock(rawstor_logging_mutex);
        return it - events.begin();
    } catch (...) {
        rawstor_mutex_unlock(rawstor_logging_mutex);
        throw;
    }
}

size_t rawstor_trace_event_begin(
    char appearance, const char* file, int line, const char* function,
    const char* format, ...
) {
    va_list args;
    va_start(args, format);
    size_t ret = rawstor_trace_event_va_begin(
        appearance, file, line, function, format, args
    );
    va_end(args);
    return ret;
}

void rawstor_trace_event_inc(size_t event) {
    rawstor_mutex_lock(rawstor_logging_mutex);
    try {
        assert(events[event].state() == EVENT_AVAILABLE);
        events[event].inc();
        rawstor_mutex_unlock(rawstor_logging_mutex);
    } catch (...) {
        rawstor_mutex_unlock(rawstor_logging_mutex);
        throw;
    }
}

void rawstor_trace_event_dec(size_t event) {
    rawstor_mutex_lock(rawstor_logging_mutex);
    try {
        assert(events[event].state() == EVENT_AVAILABLE);
        size_t refs = events[event].dec();
        if (refs == 0) {
            events[event].deleting();
            rawstor_trace_event_dump();
            dprintf(STDERR_FILENO, "TRACE\n");
        }
        rawstor_mutex_unlock(rawstor_logging_mutex);
    } catch (...) {
        rawstor_mutex_unlock(rawstor_logging_mutex);
        throw;
    }
}

void rawstor_trace_event_va_message(
    size_t event, const char* file, int line, const char* function,
    const char* format, va_list args
) {
    rawstor_mutex_lock(rawstor_logging_mutex);
    try {
        assert(events[event].state() == EVENT_AVAILABLE);
        events[event].message();

        rawstor_trace_event_dump();

        dprintf(STDERR_FILENO, "TRACE %s:%d %s(): ", file, line, function);

        vdprintf(STDERR_FILENO, format, args);

        rawstor_mutex_unlock(rawstor_logging_mutex);
    } catch (...) {
        rawstor_mutex_unlock(rawstor_logging_mutex);
        throw;
    }
}

void rawstor_trace_event_message(
    size_t event, const char* file, int line, const char* function,
    const char* format, ...
) {
    va_list args;
    va_start(args, format);
    rawstor_trace_event_va_message(event, file, line, function, format, args);
    va_end(args);
}

void rawstor_trace_event_dump(void) {
    for (Event& event : events) {
        char ch = '?';
        switch (event.state()) {
        case EVENT_CREATING:
            ch = '+';
            event.available();
            break;
        case EVENT_AVAILABLE:
            ch = event.appearance();
            break;
        case EVENT_MESSAGE:
            ch = '*';
            event.available();
            break;
        case EVENT_DELETING:
            ch = '-';
            event.deleted();
            break;
        case EVENT_DELETED:
            ch = ' ';
            break;
        }
        dprintf(STDERR_FILENO, "%c ", ch);
    }
}

#endif // RAWSTOR_TRACE_EVENTS
