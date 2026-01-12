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

class TaskBuffered : public Task {
protected:
    void* _buffer;

public:
    TaskBuffered() : _buffer(nullptr) {}
    virtual ~TaskBuffered() override = default;

    inline void set(void* buffer) noexcept { _buffer = buffer; }

    /**
     * size: must be a power of two.
     */
    virtual unsigned int size() const noexcept = 0;
    /**
     * count: must be a power of two.
     */
    virtual unsigned int count() const noexcept = 0;
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

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TASK_HPP
