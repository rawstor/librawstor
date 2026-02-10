#ifndef RAWSTORIO_TASK_HPP
#define RAWSTORIO_TASK_HPP

#include <rawstorstd/logging.hpp>

#include <sys/uio.h>

#include <string>

namespace rawstor {
namespace io {

class Task {
private:
    int _fd;

public:
    rawstor::TraceEvent trace_event;

    explicit Task(int fd);
    Task(const Task&) = delete;
    Task(Task&&) = delete;
    virtual ~Task() = default;
    Task& operator=(const Task&) = delete;
    Task& operator=(Task&&) = delete;

    inline int fd() const noexcept { return _fd; }

    virtual void operator()(size_t result, int error) = 0;
};

class TaskScalar : public Task {
public:
    explicit TaskScalar(int fd);
    virtual ~TaskScalar() override = default;

    virtual void* buf() noexcept = 0;
    virtual size_t size() const noexcept = 0;
};

class TaskVector : public Task {
public:
    explicit TaskVector(int fd);
    virtual ~TaskVector() override = default;

    virtual iovec* iov() noexcept = 0;
    virtual unsigned int niov() const noexcept = 0;
    virtual size_t size() const noexcept = 0;
};

class TaskScalarPositional : public TaskScalar {
public:
    explicit TaskScalarPositional(int fd);
    virtual ~TaskScalarPositional() override = default;

    virtual off_t offset() const noexcept = 0;
};

class TaskVectorPositional : public TaskVector {
public:
    explicit TaskVectorPositional(int fd);
    virtual ~TaskVectorPositional() override = default;

    virtual off_t offset() const noexcept = 0;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TASK_HPP
