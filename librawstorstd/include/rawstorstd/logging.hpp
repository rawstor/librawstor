#ifndef RAWSTOR_LOGGING_HPP
#define RAWSTOR_LOGGING_HPP

#include <rawstorstd/logging.h>

#include <cassert>
#include <sstream>
#include <string>
#include <utility>

namespace rawstor {

#define RAWSTOR_TRACE_EVENT(appearance, message)                               \
    TraceEvent((appearance), __FILE__, __LINE__, __FUNCTION__, message)

#ifdef RAWSTOR_TRACE_EVENTS
#define RAWSTOR_TRACE_EVENT_MESSAGE(trace, stream)                             \
    do {                                                                       \
        std::ostringstream oss;                                                \
        oss << stream;                                                         \
        trace.message(__FILE__, __LINE__, __FUNCTION__, oss.str());            \
    } while (0)
#else
#define RAWSTOR_TRACE_EVENT_MESSAGE(trace, stream)
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
        const std::string& message
    ) noexcept
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(rawstor_trace_event_begin(
            appearance, file, line, function, "%s\n", message.c_str()
        )),
        _file(file),
        _line(line),
        _function(function)
#endif
    {
#ifndef RAWSTOR_TRACE_EVENTS
        (void)(appearance);
        (void)(file);
        (void)(line);
        (void)(function);
        (void)(message);
#endif
    }

    TraceEvent(const TraceEvent&) = delete;

    TraceEvent(TraceEvent&& other) noexcept
#ifdef RAWSTOR_TRACE_EVENTS
        :
        _id(std::exchange(other._id, (size_t)-1)),
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
        if (_id != (size_t)-1) {
            rawstor_trace_event_end(_id, _file, _line, _function, "end\n");
        }
#endif
    }

    TraceEvent& operator=(const TraceEvent&) = delete;
    TraceEvent& operator=(TraceEvent&& other) {
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
        const char* file, int line, const char* function,
        const std::string& message
    ) const noexcept {
#ifdef RAWSTOR_TRACE_EVENTS
        assert(_id != (size_t)-1);
        rawstor_trace_event_message(
            _id, file, line, function, "%s\n", message.c_str()
        );
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
