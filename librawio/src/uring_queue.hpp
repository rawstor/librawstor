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

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth);
    ~Queue();

    rawio::Event* poll(
        int fd, unsigned int mask, std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* poll_multishot(
        int fd, unsigned int mask, std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event* accept(
        int fd, sockaddr* addr, socklen_t* addrlen,
        std::function<void(size_t, int)>&& cb
    ) override;

    rawio::Event*
    accept_multishot(int fd, std::function<void(size_t, int)>&& cb) override;

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

    void wait(int timeout) override;
};

} // namespace uring
} // namespace rawio

#endif // RAWIO_URING_QUEUE_HPP
