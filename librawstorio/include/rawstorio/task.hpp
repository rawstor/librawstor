#ifndef RAWSTORIO_TASK_HPP
#define RAWSTORIO_TASK_HPP

#include <rawstorstd/logging.h>

#include <sys/socket.h>
#include <sys/uio.h>

#include <string>

namespace rawstor {
namespace io {

class Task {
private:
    int _fd;

#ifdef RAWSTOR_TRACE_EVENTS
    size_t _trace_id;
#endif

public:
    explicit Task(int fd);
    Task(const Task&) = delete;
    Task(Task&&) = delete;
    virtual ~Task();
    Task& operator=(const Task&) = delete;
    Task& operator=(Task&&) = delete;

    inline int fd() const noexcept { return _fd; }

    virtual void operator()(size_t result, int error) = 0;

#ifdef RAWSTOR_TRACE_EVENTS
    void trace(
        const char* file, int line, const char* function,
        const std::string& message
    );
#endif
};

class TaskPoll : public Task {
public:
    explicit TaskPoll(int fd);
    virtual ~TaskPoll() override = default;

    virtual unsigned int mask() const noexcept = 0;
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

class TaskMessage : public Task {
public:
    explicit TaskMessage(int fd);
    virtual ~TaskMessage() override = default;

    virtual msghdr* msg() noexcept = 0;
    virtual size_t size() const noexcept = 0;
    virtual int flags() const noexcept = 0;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TASK_HPP
