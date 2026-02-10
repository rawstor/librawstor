#ifndef RAWSTOR_LOGGING_HPP
#define RAWSTOR_LOGGING_HPP

#include <rawstorstd/logging.h>

#include <cassert>
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
    const char* _file;
    int _line;
    const char* _function;
#endif

public:
    TraceEvent(
        char appearance, const char* file, int line, const char* function,
        const char* format, ...
    ) noexcept
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(static_cast<size_t>(-1)),
        _file(file),
        _line(line),
        _function(function)
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

    TraceEvent(const TraceEvent&) = delete;

    TraceEvent(TraceEvent&& other) noexcept
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(std::exchange(other._id, static_cast<size_t>(-1))),
        _file(other._file),
        _line(other._line),
        _function(other._function)
#endif
    {
#ifndef RAWSTOR_TRACE_EVENTS
        (void)(other);
#endif
    }

    ~TraceEvent() {
#ifdef RAWSTOR_TRACE_EVENTS
        if (_id != static_cast<size_t>(-1)) {
            rawstor_trace_event_end(_id, _file, _line, _function, "end\n");
        }
#endif
    }

    TraceEvent& operator=(const TraceEvent&) = delete;
    TraceEvent& operator=(TraceEvent&& other) noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
        std::swap(_id, other._id);
        std::swap(_file, other._file);
        std::swap(_line, other._line);
        std::swap(_function, other._function);
#else
        (void)(other);
#endif
        return *this;
    }

    void message(
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
        (void)(message);
#endif
    }
};

} // namespace rawstor

#endif // RAWSTOR_LOGGING_HPP
