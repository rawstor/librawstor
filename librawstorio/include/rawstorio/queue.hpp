#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include <memory>
#include <string>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {

class Task;

class TaskPollMultishot;

class TaskScalar;

class TaskVector;

class TaskMessage;

class TaskVectorExternal;

typedef void Event;

class Queue {
private:
    unsigned int _depth;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);
    static std::unique_ptr<Queue> create(unsigned int depth);

    explicit Queue(unsigned int depth);
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;
    virtual ~Queue() = default;
    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;

    inline unsigned int depth() const noexcept { return _depth; }

    virtual Event* poll(int fd, std::unique_ptr<Task> t, unsigned int mask) = 0;
    virtual Event*
    poll_multishot(int fd, std::unique_ptr<Task> t, unsigned int mask) = 0;

    virtual Event* read(int fd, std::unique_ptr<TaskScalar> t) = 0;
    virtual Event* readv(int fd, std::unique_ptr<TaskVector> t) = 0;
    virtual Event*
    pread(int fd, std::unique_ptr<TaskScalar> t, off_t offset) = 0;
    virtual Event*
    preadv(int fd, std::unique_ptr<TaskVector> t, off_t offset) = 0;
    virtual Event*
    recv(int fd, std::unique_ptr<TaskScalar> t, unsigned int flags) = 0;
    /**
     * entry_size: must be a power of two.
     * entries: must be a power of two.
     */
    virtual Event* recv_multishot(
        int fd, std::unique_ptr<TaskVectorExternal> t, size_t entry_size,
        unsigned int entries, unsigned int flags
    ) = 0;
    virtual Event*
    recvmsg(int fd, std::unique_ptr<TaskMessage> t, unsigned int flags) = 0;

    virtual Event* write(int fd, std::unique_ptr<TaskScalar> t) = 0;
    virtual Event* writev(int fd, std::unique_ptr<TaskVector> t) = 0;
    virtual Event*
    pwrite(int fd, std::unique_ptr<TaskScalar> t, off_t offset) = 0;
    virtual Event*
    pwritev(int fd, std::unique_ptr<TaskVector> t, off_t offset) = 0;
    virtual Event*
    send(int fd, std::unique_ptr<TaskScalar> t, unsigned int flags) = 0;
    virtual Event*
    sendmsg(int fd, std::unique_ptr<TaskMessage> t, unsigned int flags) = 0;

    virtual void cancel(Event* event) = 0;

    virtual void wait(unsigned int timeout) = 0;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_QUEUE_HPP
