#include <rawstorio/task.hpp>

#include <rawstorstd/logging.h>

namespace rawstor {
namespace io {

Task::Task(int fd) :
    _fd(fd)
#ifdef RAWSTOR_TRACE_EVENTS
    ,
    _trace_id(rawstor_trace_event_begin(
        '|', __FILE__, __LINE__, __FUNCTION__, "fd %d\n", _fd
    ))
#endif
{
}

Task::~Task() {
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace_event_end(
        _trace_id, __FILE__, __LINE__, __FUNCTION__, "fd %d\n", _fd
    );
#endif
}

#ifdef RAWSTOR_TRACE_EVENTS
void Task::trace(
    const char* file, int line, const char* function, const std::string& message
) {
    rawstor_trace_event_message(
        _trace_id, file, line, function, "%s\n", message.c_str()
    );
}
#endif

TaskScalar::TaskScalar(int fd) : Task(fd) {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "");
#endif
}

TaskVector::TaskVector(int fd) : Task(fd) {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "");
#endif
}

TaskMessage::TaskMessage(int fd) : Task(fd) {
#ifdef RAWSTOR_TRACE_EVENTS
    trace(__FILE__, __LINE__, __FUNCTION__, "");
#endif
}

} // namespace io
} // namespace rawstor
