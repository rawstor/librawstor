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

        Queue(unsigned int depth);
        ~Queue();

        inline io_uring* ring() noexcept { return &_ring; }

        void poll(std::unique_ptr<rawstor::io::TaskPoll> t) override;

        void read(std::unique_ptr<rawstor::io::TaskScalar> t) override;

        void read(std::unique_ptr<rawstor::io::TaskVector> t) override;

        void
        read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

        void
        read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

        void read(std::unique_ptr<rawstor::io::TaskMessage> t) override;

        void write(std::unique_ptr<rawstor::io::TaskScalar> t) override;

        void write(std::unique_ptr<rawstor::io::TaskVector> t) override;

        void
        write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

        void
        write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

        void write(std::unique_ptr<rawstor::io::TaskMessage> t) override;

        bool empty() const noexcept override;

        void wait(unsigned int timeout) override;
};

} // namespace uring
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_URING_QUEUE_HPP
