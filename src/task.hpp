#ifndef RAWSTOR_TASK_HPP
#define RAWSTOR_TASK_HPP

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor/object.h>

#include <sys/uio.h>

namespace rawstor {

class Task {
    private:
#ifdef RAWSTOR_TRACE_EVENTS
        size_t _trace_id;
#endif

    public:
        Task()
#ifdef RAWSTOR_TRACE_EVENTS
            :
            _trace_id(rawstor_trace_event_begin(
                'I', __FILE__, __LINE__, __FUNCTION__, "\n"
            ))
#endif
        {
        }
        Task(const Task&) = delete;
        Task(Task&&) = delete;
        virtual ~Task() {
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace_event_end(
                _trace_id, __FILE__, __LINE__, __FUNCTION__, "\n"
            );
#endif
        }

        Task& operator=(const Task&) = delete;
        Task& operator=(Task&&) = delete;

        virtual void operator()(RawstorObject* o, size_t result, int error) = 0;

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(
            const char* file, int line, const char* function,
            const std::string& message
        ) {
            rawstor_trace_event_message(
                _trace_id, file, line, function, "%s\n", message.c_str()
            );
        }
#endif
};

class TaskScalar : public Task {
    public:
        TaskScalar() : Task() {}

        virtual void* buf() noexcept = 0;

        virtual size_t size() const noexcept = 0;

        virtual off_t offset() const noexcept = 0;
};

class TaskVector : public Task {
    public:
        TaskVector() : Task() {}

        virtual iovec* iov() noexcept = 0;

        virtual unsigned int niov() const noexcept = 0;

        virtual size_t size() const noexcept = 0;

        virtual off_t offset() const noexcept = 0;
};

} // namespace rawstor

#endif // RAWSTOR_TASK_HPP
