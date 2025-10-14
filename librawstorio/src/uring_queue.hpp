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
            int fd,
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void readv(
            int fd,
            iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void pread(
            int fd,
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        void preadv(
            int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        void write(
            int fd,
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void writev(
            int fd,
            iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void pwrite(
            int fd,
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        void pwritev(
            int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        bool empty() const noexcept;

        RawstorIOEvent* wait_event(unsigned int timeout);

        void release_event(RawstorIOEvent *event) noexcept;
};


}}} // rawstor::io::uring

#endif // RAWSTORIO_URING_QUEUE_HPP
