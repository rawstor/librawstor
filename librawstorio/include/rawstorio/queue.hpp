#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include <rawstor/io_queue.h>

#include <string>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {


class Queue {
    private:
        unsigned int _depth;

    public:
        static std::string engine_name();
        static void setup_fd(int fd);
        static Queue* create(unsigned int depth);

        Queue(unsigned int depth): _depth(depth) {}
        Queue(const Queue &) = delete;
        Queue(Queue &&) = delete;
        virtual ~Queue() {}
        Queue& operator=(const Queue &) = delete;
        Queue& operator=(Queue &&) = delete;

        inline unsigned int depth() const noexcept {
            return _depth;
        }

        virtual void read(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void readv(
            int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void pread(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void preadv(
            int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void write(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void writev(
            int fd,
            iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void pwrite(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data) = 0;

        virtual void pwritev(
            int fd,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data) = 0;

        virtual RawstorIOEvent* wait_event(unsigned int timeout) = 0;

        virtual void release_event(RawstorIOEvent *event) noexcept = 0;
};


}} // rawstor::io


#endif // RAWSTORIO_QUEUE_HPP
