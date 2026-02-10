#include <rawstorio/task.hpp>

namespace rawstor {
namespace io {

Task::Task(int fd) :
    _fd(fd),
    trace_event(RAWSTOR_TRACE_EVENT('|', "%s\n", "")) {
}

TaskScalar::TaskScalar(int fd) : Task(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "");
}

TaskVector::TaskVector(int fd) : Task(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "");
}

TaskScalarPositional::TaskScalarPositional(int fd) : TaskScalar(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "");
}

TaskVectorPositional::TaskVectorPositional(int fd) : TaskVector(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "");
}

} // namespace io
} // namespace rawstor
