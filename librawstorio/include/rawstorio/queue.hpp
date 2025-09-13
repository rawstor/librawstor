#ifndef RAWSTORIO_QUEUE_HPP
#define RAWSTORIO_QUEUE_HPP

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <cstddef>
#include <cstdio>

namespace rawstor {
namespace io {


class Queue {
    private:
        RawstorIOQueue *_impl;

    public:
        Queue(unsigned int depth);
        Queue(const Queue &) = delete;
        ~Queue();

        Queue& operator=(const Queue &) = delete;

        void read(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data);

        void readv(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);

        void pread(
            int fd, void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void preadv(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void write(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data);

        void pwrite(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void writev(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);

        void pwritev(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        RawstorIOEvent* wait_event_timeout(unsigned int timeout);

        void release_event(RawstorIOEvent *event);

};



} // io
} // rawstor

#endif // RAWSTORIO_QUEUE_HPP
