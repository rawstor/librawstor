#ifndef RAWSTOR_TASK_HPP
#define RAWSTOR_TASK_HPP

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.hpp>

#include <rawstor/object.h>

#include <sys/uio.h>

namespace rawstor {

class Task {
private:
public:
    TraceEvent trace_event;

    Task() : trace_event(RAWSTOR_TRACE_EVENT('I', "")) {}

    Task(const Task&) = delete;
    Task(Task&&) = delete;
    virtual ~Task() = default;

    Task& operator=(const Task&) = delete;
    Task& operator=(Task&&) = delete;

    virtual void operator()(RawstorObject* o, size_t result, int error) = 0;
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
