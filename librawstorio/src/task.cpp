#include <rawstorio/task.hpp>

namespace rawstor {
namespace io {

Task::Task(int fd) : _fd(fd), trace_event(RAWSTOR_TRACE_EVENT('|', "")) {
}

TaskScalar::TaskScalar(int fd) : Task(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "");
}

TaskVector::TaskVector(int fd) : Task(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "");
}

TaskScalarPositional::TaskScalarPositional(int fd) : TaskScalar(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "");
}

TaskVectorPositional::TaskVectorPositional(int fd) : TaskVector(fd) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "");
}

} // namespace io
} // namespace rawstor
