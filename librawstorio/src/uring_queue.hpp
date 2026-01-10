#ifndef RAWSTORIO_URING_QUEUE_HPP
#define RAWSTORIO_URING_QUEUE_HPP

#include <rawstorstd/gpp.hpp>

#include <rawstorio/queue.hpp>

#include <liburing.h>

#include <memory>

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

    inline io_uring_sqe* get_sqe() {
        io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
        if (sqe == nullptr) {
            RAWSTOR_THROW_SYSTEM_ERROR(ENOBUFS);
        }
        return sqe;
    }

    rawstor::io::Event* poll(std::unique_ptr<rawstor::io::TaskPoll> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskScalar> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskVector> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskMessage> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskScalar> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskVector> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskMessage> t) override;

    void cancel(rawstor::io::Event* event);

    void wait(unsigned int timeout) override;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_QUEUE_HPP
