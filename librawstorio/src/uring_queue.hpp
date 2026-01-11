#ifndef RAWSTORIO_URING_QUEUE_HPP
#define RAWSTORIO_URING_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <liburing.h>

#include <memory>

namespace rawstor {
namespace io {
namespace uring {

class Queue final : public rawstor::io::Queue {
private:
    io_uring _ring;
    unsigned int _events;

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth);
    ~Queue();

    rawstor::io::Event*
    poll(int fd, std::unique_ptr<rawstor::io::Task> t, int mask) override;

    rawstor::io::Event*
    read(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) override;

    rawstor::io::Event*
    readv(int fd, std::unique_ptr<rawstor::io::TaskVector> t) override;

    rawstor::io::Event* pread(
        int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset
    ) override;

    rawstor::io::Event* preadv(
        int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
    ) override;

    rawstor::io::Event* recvmsg(
        int fd, std::unique_ptr<rawstor::io::TaskMessage> t, int flags
    ) override;

    rawstor::io::Event*
    write(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) override;

    rawstor::io::Event*
    writev(int fd, std::unique_ptr<rawstor::io::TaskVector> t) override;

    rawstor::io::Event* pwrite(
        int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset
    ) override;

    rawstor::io::Event* pwritev(
        int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
    ) override;

    rawstor::io::Event* sendmsg(
        int fd, std::unique_ptr<rawstor::io::TaskMessage> t, int flags
    ) override;

    void cancel(rawstor::io::Event* event);

    bool empty() const noexcept override;

    void wait(unsigned int timeout) override;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_QUEUE_HPP
