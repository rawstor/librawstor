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

class TaskVectorExternal : public Task {
protected:
    iovec* _iov;
    unsigned int _niov;

public:
    TaskVectorExternal();
    virtual ~TaskVectorExternal() override = default;

    inline void set(iovec* iov, unsigned int niov) noexcept {
        _iov = iov;
        _niov = niov;
    }

    virtual size_t size() const noexcept = 0;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TASK_HPP
