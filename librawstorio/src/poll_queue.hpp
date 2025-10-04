#ifndef RAWSTORIO_POLL_QUEUE_HPP
#define RAWSTORIO_POLL_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <rawstorstd/ringbuf.hpp>

#include <list>
#include <memory>
#include <string>
#include <vector>


namespace rawstor {
namespace io {
namespace poll {


class Event;


class Session;


class Queue: public rawstor::io::Queue {
    private:
        std::list<std::shared_ptr<Session>> _sessions;
        rawstor::RingBuf<Event*> _cqes;

        std::shared_ptr<Session> _get_session(int fd);

    public:
        static std::string engine_name();
        static void setup_fd(int fd);

        Queue(unsigned int depth):
            rawstor::io::Queue(depth),
            _cqes(depth)
        {}

        void read(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data);

        void readv(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);

        void pread(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void preadv(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void write(
            int fd,
            void *buf, size_t size,
            RawstorIOCallback *cb, void *data);

        void writev(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size,
            RawstorIOCallback *cb, void *data);

        void pwrite(
            int fd,
            void *buf, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        void pwritev(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorIOCallback *cb, void *data);

        rawstor::io::Event* wait_event(unsigned int timeout);

        void release_event(rawstor::io::Event *event) noexcept;
};


}}} // rawstor::io::poll


#endif // RAWSTORIO_POLL_QUEUE_HPP
