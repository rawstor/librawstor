#ifndef RAWSTORIO_URING_QUEUE_HPP
#define RAWSTORIO_URING_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <liburing.h>

#include <memory>
#include <string>

namespace rawstor {
namespace io {
namespace uring {

class Queue final : public rawstor::io::Queue {
private:
    io_uring _ring;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth);
    ~Queue();

    rawstor::io::Event* poll(
        int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* poll_multishot(
        int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* read(
        int fd, void* buf, size_t size, std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* readv(
        int fd, iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* pread(
        int fd, void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* preadv(
        int fd, iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* recv(
        int fd, void* buf, size_t size, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* recv_multishot(
        int fd, size_t entry_size, unsigned int entries, unsigned int flags,
        std::unique_ptr<rawstor::io::TaskVectorExternal> t
    ) override;

    rawstor::io::Event* recvmsg(
        int fd, msghdr* msg, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* write(
        int fd, const void* buf, size_t size,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* writev(
        int fd, const iovec* iov, unsigned int niov,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* pwrite(
        int fd, const void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* pwritev(
        int fd, const iovec* iov, unsigned int niov, off_t offset,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* send(
        int fd, const void* buf, size_t size, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    rawstor::io::Event* sendmsg(
        int fd, const msghdr* msg, unsigned int flags,
        std::unique_ptr<rawstor::io::Task> t
    ) override;

    void cancel(rawstor::io::Event* event);

    void wait(unsigned int timeout) override;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_QUEUE_HPP
