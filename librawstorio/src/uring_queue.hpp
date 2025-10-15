#ifndef RAWSTORIO_URING_QUEUE_HPP
#define RAWSTORIO_URING_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <liburing.h>

#include <memory>


namespace rawstor {
namespace io {
namespace uring {


class Queue: public rawstor::io::Queue {
    private:
        io_uring _ring;
        unsigned int _events;

    public:
        static const std::string& engine_name();
        static void setup_fd(int fd);

        Queue(unsigned int depth);
        ~Queue();

        inline io_uring* ring() noexcept {
            return &_ring;
        }

        void read(
            int fd, std::unique_ptr<rawstor::io::TaskScalar> t);

        void read(
            int fd, std::unique_ptr<rawstor::io::TaskVector> t);

        void read(
            int fd, std::unique_ptr<rawstor::io::TaskScalarPositional> t);

        void read(
            int fd, std::unique_ptr<rawstor::io::TaskVectorPositional> t);

        void write(
            int fd, std::unique_ptr<rawstor::io::TaskScalar> t);

        void write(
            int fd, std::unique_ptr<rawstor::io::TaskVector> t);

        void write(
            int fd, std::unique_ptr<rawstor::io::TaskScalarPositional> t);

        void write(
            int fd, std::unique_ptr<rawstor::io::TaskVectorPositional> t);

        bool empty() const noexcept;

        void wait(unsigned int timeout);
};


}}} // rawstor::io::uring

#endif // RAWSTORIO_URING_QUEUE_HPP
