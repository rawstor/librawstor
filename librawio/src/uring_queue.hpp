#ifndef RAWIO_URING_QUEUE_HPP
#define RAWIO_URING_QUEUE_HPP

#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

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

protected:
    void _attach(
        rawio::Event* event, std::coroutine_handle<> h, size_t* value,
        int* error
    ) noexcept override;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth);
    ~Queue();

    inline unsigned int dispatch_generation() const noexcept {
        return _dispatch_generation;
    }

    rawio::Awaitable<int>
    open(const char* path, int flags, mode_t mode) override;

    rawio::Awaitable<int> close(int fd) override;

    rawio::Awaitable<int> poll(int fd, unsigned int mask) override;

    rawio::PollStream poll_multishot(int fd, unsigned int mask) override;

    rawio::Awaitable<int>
    accept(int fd, sockaddr* addr, socklen_t* addrlen) override;

    rawio::AcceptStream accept_multishot(int fd) override;

    rawio::Awaitable<int>
    connect(int fd, const sockaddr* addr, socklen_t addrlen) override;

    rawio::Awaitable<size_t> read(int fd, void* buf, size_t size) override;

    rawio::Awaitable<size_t>
    readv(int fd, iovec* iov, unsigned int niov) override;

    rawio::Awaitable<size_t>
    pread(int fd, void* buf, size_t size, off_t offset) override;

    rawio::Awaitable<size_t>
    preadv(int fd, iovec* iov, unsigned int niov, off_t offset) override;

    rawio::Awaitable<size_t>
    recv(int fd, void* buf, size_t size, unsigned int flags) override;

    rawio::RecvStream recv_multishot(
        int fd, size_t entry_size, unsigned int entries, size_t size,
        unsigned int flags
    ) override;

    rawio::Awaitable<size_t>
    recvmsg(int fd, msghdr* msg, unsigned int flags) override;

    rawio::Awaitable<size_t>
    write(int fd, const void* buf, size_t size) override;

    rawio::Awaitable<size_t>
    writev(int fd, const iovec* iov, unsigned int niov) override;

    rawio::Awaitable<size_t> pwrite(
        int fd, const void* buf, size_t size, off_t offset, bool sync
    ) override;

    rawio::Awaitable<size_t> pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset, bool sync
    ) override;

    rawio::Awaitable<int> fsync(int fd, bool datasync) override;

    rawio::Awaitable<int>
    fallocate(int fd, int mode, off_t offset, off_t len) override;

    rawio::Awaitable<size_t>
    send(int fd, const void* buf, size_t size, unsigned int flags) override;

    rawio::Awaitable<size_t>
    sendmsg(int fd, const msghdr* msg, unsigned int flags) override;

    rawio::Awaitable<void> timeout(unsigned int usec) override;

    rawio::Awaitable<void> cancel(rawio::Event* event) override;

    rawio::Awaitable<void> cancel(int fd) override;

    void wait() override;

    void wait_timeout(unsigned int msec) override;
};

} // namespace uring
} // namespace rawio

#endif // RAWIO_URING_QUEUE_HPP
