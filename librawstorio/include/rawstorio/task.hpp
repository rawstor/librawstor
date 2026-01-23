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
#ifdef RAWSTOR_TRACE_EVENTS
    size_t _trace_id;
#endif

public:
    Task();
    Task(const Task&) = delete;
    Task(Task&&) = delete;
    virtual ~Task();
    Task& operator=(const Task&) = delete;
    Task& operator=(Task&&) = delete;

    virtual void operator()(size_t result, int error) = 0;

#ifdef RAWSTOR_TRACE_EVENTS
    void trace(
        const char* file, int line, const char* function,
        const std::string& message
    );
#endif
};

class TaskScalar : public Task {
public:
    TaskScalar();
    virtual ~TaskScalar() override = default;

    virtual void* buf() noexcept = 0;
    virtual size_t size() const noexcept = 0;
};

class TaskVector : public Task {
public:
    TaskVector();
    virtual ~TaskVector() override = default;

    virtual iovec* iov() noexcept = 0;
    virtual unsigned int niov() const noexcept = 0;
    virtual size_t size() const noexcept = 0;
};

class TaskMessage : public Task {
public:
    TaskMessage();
    virtual ~TaskMessage() override = default;

    virtual msghdr* msg() noexcept = 0;
    virtual size_t size() const noexcept = 0;
};

class TaskVectorExternal : public TaskVector {
private:
    iovec* _iov;
    unsigned int _niov;

public:
    TaskVectorExternal() : _iov(nullptr), _niov(0) {}
    virtual ~TaskVectorExternal() override = default;

    inline void set(iovec* iov, unsigned int niov) noexcept {
        _iov = iov;
        _niov = niov;
    }

    iovec* iov() noexcept { return _iov; }
    virtual unsigned int niov() const noexcept { return _niov; }
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TASK_HPP
