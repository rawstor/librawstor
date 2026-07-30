#ifndef RAWIO_URING_QUEUE_HPP
#define RAWIO_URING_QUEUE_HPP

#include <rawio/queue.hpp>

#include <liburing.h>

#include <memory>
#include <string>

namespace rawio {
namespace uring {

class Queue final : public rawio::Queue {
private:
    io_uring _ring;

    /*
     * Bumped once per _dispatch() call (one reap of the completion ring).
     * IORING_POLL_ADD_MULTI can post more than one completion for a
     * single registration within the very same reap batch -- eventfd_write()
     * wakes the poll waitqueue on every write, so N writes coalesced
     * before we get around to draining can yield N CQEs even though a
     * single read() would drain all of them at once. Handing every one
     * of those to the caller's callback lets it observe "readable" with
     * nothing left to read (e.g. eventfd EAGAIN) purely because an
     * earlier callback in the *same* batch already drained it.
     * poll_multishot() callbacks compare their own last-seen generation
     * against this counter to collapse such same-batch duplicates into a
     * single callback invocation.
     */
    unsigned int _dispatch_generation;

    void _dispatch();

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth);
    ~Queue();

    rawio::Event* open(
        const char* path, int flags, mode_t mode, std::function<void(int)>&& cb
    );

    rawio::Event* close(int fd, std::function<void(int)>&& cb);

    rawio::Event*
    poll(int fd, unsigned int mask, std::function<void(int)>&& cb) override;

    rawio::Event* poll_multishot(
        int fd, unsigned int mask, std::function<void(int)>&& cb
    ) override;

    rawio::Event* accept(
        int fd, sockaddr* addr, socklen_t* addrlen,
        std::function<void(int)>&& cb
    ) override;

    rawio::Event*
    accept_multishot(int fd, std::function<void(int)>&& cb) override;

    rawio::Event* connect(
        int fd, const sockaddr* addr, socklen_t addrlen,
        std::function<void(int)>&& cb
    ) override;

    rawio::Event* read(
        int fd, void* buf, size_t size, std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* readv(
        int fd, iovec* iov, unsigned int niov,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* pread(
        int fd, void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* preadv(
        int fd, iovec* iov, unsigned int niov, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* recv(
        int fd, void* buf, size_t size, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* recv_multishot(
        int fd, size_t entry_size, unsigned int entries, size_t size,
        unsigned int flags,
        std::function<size_t(const iovec*, unsigned int, size_t, int)>&& cb
    ) override;

    rawio::Event* recvmsg(
        int fd, msghdr* msg, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* write(
        int fd, const void* buf, size_t size,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* writev(
        int fd, const iovec* iov, unsigned int niov,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* pwrite(
        int fd, const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* send(
        int fd, const void* buf, size_t size, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* sendmsg(
        int fd, const msghdr* msg, unsigned int flags,
        std::function<void(size_t, int)>&& cb
    ) override;

    void cancel(rawio::Event* event);

    void cancel(int fd);

    void wait() override;

    void wait_timeout(unsigned int timeout) override;
};

} // namespace uring
} // namespace rawio

#endif // RAWIO_URING_QUEUE_HPP
