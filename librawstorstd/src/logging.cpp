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

public:
    explicit Event(char appearance) :
        _appearance(appearance),
        _state(EVENT_CREATING) {}

    char appearance() const noexcept { return _appearance; }

    EventState state() const noexcept { return _state; }

    void deleting() noexcept { _state = EVENT_DELETING; }

    void message() noexcept { _state = EVENT_MESSAGE; }

    void available() noexcept { _state = EVENT_AVAILABLE; }

    void deleted() noexcept { _state = EVENT_DELETED; }
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

size_t rawstor_trace_event_begin(
    char appearance, const char* file, int line, const char* function,
    const char* format, ...
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

        va_list args;
        va_start(args, format);
        vdprintf(STDERR_FILENO, format, args);
        va_end(args);

        rawstor_mutex_unlock(rawstor_logging_mutex);
        return it - events.begin();
    } catch (...) {
        rawstor_mutex_unlock(rawstor_logging_mutex);
        throw;
    }
}

void rawstor_trace_event_end(
    size_t event, const char* file, int line, const char* function,
    const char* format, ...
) {
    rawstor_mutex_lock(rawstor_logging_mutex);
    try {
        assert(events[event].state() == EVENT_AVAILABLE);
        events[event].deleting();

        rawstor_trace_event_dump();

        dprintf(STDERR_FILENO, "TRACE %s:%d %s(): ", file, line, function);

        va_list args;
        va_start(args, format);
        vdprintf(STDERR_FILENO, format, args);
        va_end(args);

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
    rawstor_mutex_lock(rawstor_logging_mutex);
    try {
        assert(events[event].state() == EVENT_AVAILABLE);
        events[event].message();

        rawstor_trace_event_dump();

        dprintf(STDERR_FILENO, "TRACE %s:%d %s(): ", file, line, function);

        va_list args;
        va_start(args, format);
        vdprintf(STDERR_FILENO, format, args);
        va_end(args);

        rawstor_mutex_unlock(rawstor_logging_mutex);
    } catch (...) {
        rawstor_mutex_unlock(rawstor_logging_mutex);
        throw;
    }
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
