#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include <memory>
#include <string>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {

class Task;

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

    virtual Event* poll(int fd, unsigned int mask, std::unique_ptr<Task> t) = 0;
    virtual Event*
    poll_multishot(int fd, unsigned int mask, std::unique_ptr<Task> t) = 0;

    virtual Event*
    read(int fd, void* buf, size_t size, std::unique_ptr<Task> t) = 0;
    virtual Event*
    readv(int fd, iovec* iov, unsigned int niov, std::unique_ptr<Task> t) = 0;
    virtual Event* pread(
        int fd, void* buf, size_t size, off_t offset, std::unique_ptr<Task> t
    ) = 0;
    virtual Event* preadv(
        int fd, iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<Task> t
    ) = 0;
    virtual Event* recv(
        int fd, void* buf, size_t size, unsigned int flags,
        std::unique_ptr<Task> t
    ) = 0;
    /**
     * entry_size: must be a power of two.
     * entries: must be a power of two.
     */
    virtual Event* recv_multishot(
        int fd, size_t entry_size, unsigned int entries, unsigned int flags,
        std::unique_ptr<TaskVectorExternal> t
    ) = 0;
    virtual Event* recvmsg(
        int fd, msghdr* msg, unsigned int flags, std::unique_ptr<Task> t
    ) = 0;

    virtual Event*
    write(int fd, const void* buf, size_t size, std::unique_ptr<Task> t) = 0;
    virtual Event* writev(
        int fd, const iovec* iov, unsigned int niov, std::unique_ptr<Task> t
    ) = 0;
    virtual Event* pwrite(
        int fd, const void* buf, size_t size, off_t offset,
        std::unique_ptr<Task> t
    ) = 0;
    virtual Event* pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<Task> t
    ) = 0;
    virtual Event* send(
        int fd, const void* buf, size_t size, unsigned int flags,
        std::unique_ptr<Task> t
    ) = 0;
    virtual Event* sendmsg(
        int fd, const msghdr* msg, unsigned int flags, std::unique_ptr<Task> t
    ) = 0;

    virtual void cancel(Event* event) = 0;

    virtual void wait(unsigned int timeout) = 0;
};

} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_QUEUE_HPP
