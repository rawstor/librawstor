#ifndef RAWSTD_LOGGING_HPP
#define RAWSTD_LOGGING_HPP

#include <rawstd/logging.h>

#include <cassert>
#include <cstdarg>
#include <sstream>
#include <string>
#include <utility>

namespace rawstd {

#define RAWSTD_TRACE_EVENT(appearance, format, ...)                            \
    rawstd::TraceEvent(                                                        \
        (appearance), __FILE__, __LINE__, __FUNCTION__, format, __VA_ARGS__    \
    )

#ifdef RAWSTD_TRACE_EVENTS
#define RAWSTD_TRACE_EVENT_MESSAGE(trace_event, format, ...)                   \
    trace_event.message(__FILE__, __LINE__, __FUNCTION__, format, __VA_ARGS__)
#else
#define RAWSTD_TRACE_EVENT_MESSAGE(trace_event, format, ...) (void)(trace_event)
#endif

class TraceEvent final {
private:
#ifdef RAWSTD_TRACE_EVENTS
    size_t _id;
#endif

public:
    TraceEvent(
        char appearance, const char* file, int line, const char* function,
        const char* format, ...
    )
#ifdef RAWSTD_TRACE_EVENTS
        :
        _id(static_cast<size_t>(-1))
#endif
    {
#ifdef RAWSTD_TRACE_EVENTS
        va_list args;
        va_start(args, format);
        _id = rawstd_trace_event_va_begin(
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

    TraceEvent(const TraceEvent& other)
#ifdef RAWSTD_TRACE_EVENTS
        :
        _id(other._id)
#endif
    {
#ifdef RAWSTD_TRACE_EVENTS
        rawstd_trace_event_inc(_id);
#else
        (void)(other);
#endif
    }

    TraceEvent(TraceEvent&& other) noexcept
#ifdef RAWSTD_TRACE_EVENTS
        :
        _id(std::exchange(other._id, static_cast<size_t>(-1)))
#endif
    {
#ifndef RAWSTD_TRACE_EVENTS
        (void)(other);
#endif
    }

    ~TraceEvent() {
#ifdef RAWSTD_TRACE_EVENTS
        if (_id != static_cast<size_t>(-1)) {
            rawstd_trace_event_dec(_id);
        }
#endif
    }

    TraceEvent& operator=(const TraceEvent&) = delete;
    TraceEvent& operator=(TraceEvent&& other) noexcept {
#ifdef RAWSTD_TRACE_EVENTS
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
#ifdef RAWSTD_TRACE_EVENTS
        assert(_id != static_cast<size_t>(-1));
        va_list args;
        va_start(args, format);
        rawstd_trace_event_va_message(_id, file, line, function, format, args);
        va_end(args);
#else
        (void)(file);
        (void)(line);
        (void)(function);
        (void)(format);
#endif
    }
};

} // namespace rawstd

#endif // RAWSTD_LOGGING_HPP
