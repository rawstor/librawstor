#include <rawstorio/task.hpp>

namespace rawstor {
namespace io {

Task::Task() : trace_event(RAWSTOR_TRACE_EVENT('|', "%s\n", "")) {
}

TaskVectorExternal::TaskVectorExternal() : _iov(nullptr), _niov(0) {
    RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "%s\n", "");
}

} // namespace io
} // namespace rawstor
