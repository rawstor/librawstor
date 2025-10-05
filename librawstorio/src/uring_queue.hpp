#ifndef RAWSTORIO_URING_QUEUE_HPP
#define RAWSTORIO_URING_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <liburing.h>


namespace rawstor {
namespace io {
namespace uring {


class Queue: public rawstor::io::Queue {
    private:
        io_uring _ring;

    public:
        static std::string engine_name();
        static void setup_fd(int fd);

        Queue(unsigned int depth);
        ~Queue();

        inline io_uring* ring() noexcept {
            return &_ring;
        }

        void read(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data);

        void readv(
            int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);

        void pread(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void preadv(
            int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void write(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data);

        void writev(
            int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);

        void pwrite(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void pwritev(
            int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        RawstorIOEvent* wait_event(unsigned int timeout);

        void release_event(RawstorIOEvent *event) noexcept;
};


}}} // rawstor::io::uring

#endif // RAWSTORIO_URING_QUEUE_HPP
