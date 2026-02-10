#ifndef RAWSTOR_LOGGING_HPP
#define RAWSTOR_LOGGING_HPP

#include <rawstorstd/logging.h>

#include <cassert>
#include <cstdarg>
#include <sstream>
#include <string>
#include <utility>

namespace rawstor {

#define RAWSTOR_TRACE_EVENT(appearance, format, ...)                           \
    TraceEvent(                                                                \
        (appearance), __FILE__, __LINE__, __FUNCTION__, format, __VA_ARGS__    \
    )

#ifdef RAWSTOR_TRACE_EVENTS
#define RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, format, ...)                  \
    trace_event.message(__FILE__, __LINE__, __FUNCTION__, format, __VA_ARGS__)
#else
#define RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, format, ...)
#endif

class TraceEvent final {
private:
#ifdef RAWSTOR_TRACE_EVENTS
    size_t _id;
#endif

public:
    TraceEvent(
        char appearance, const char* file, int line, const char* function,
        const char* format, ...
    )
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(static_cast<size_t>(-1))
#endif
    {
#ifdef RAWSTOR_TRACE_EVENTS
        va_list args;
        va_start(args, format);
        _id = rawstor_trace_event_va_begin(
            appearance, file, line, function, format, args
        );
        va_end(args);
#else
        (void)(appearance);
        (void)(file);
        (void)(line);
        (void)(function);
        (void)(format);
#endif
    }

    TraceEvent(const TraceEvent& other) noexcept
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(other._id)
#endif
    {
#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace_event_inc(_id);
#else
        (void)(other);
#endif
    }

    TraceEvent(TraceEvent&& other) noexcept
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(std::exchange(other._id, static_cast<size_t>(-1)))
#endif
    {
#ifndef RAWSTOR_TRACE_EVENTS
        (void)(other);
#endif
    }

    ~TraceEvent() {
#ifdef RAWSTOR_TRACE_EVENTS
        if (_id != static_cast<size_t>(-1)) {
            rawstor_trace_event_dec(_id);
        }
#endif
    }

    TraceEvent& operator=(const TraceEvent&) = delete;
    TraceEvent& operator=(TraceEvent&& other) noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
        std::swap(_id, other._id);
#else
        (void)(other);
#endif
        return *this;
    }

    inline void message(
        const char* file, int line, const char* function, const char* format,
        ...
    ) const noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
        assert(_id != static_cast<size_t>(-1));
        va_list args;
        va_start(args, format);
        rawstor_trace_event_va_message(_id, file, line, function, format, args);
        va_end(args);
#else
        (void)(file);
        (void)(line);
        (void)(function);
        (void)(format);
#endif
    }
};

} // namespace rawstor

#endif // RAWSTOR_LOGGING_HPP
