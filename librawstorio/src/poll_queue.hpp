#ifndef RAWSTORIO_POLL_QUEUE_HPP
#define RAWSTORIO_POLL_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <rawstorstd/ringbuf.hpp>

#include <unordered_map>
#include <memory>
#include <string>


namespace rawstor {
namespace io {
namespace poll {


class Event;

class Session;


class Queue: public rawstor::io::Queue {
    private:
        std::unordered_map<int, std::shared_ptr<Session>> _sessions;
        rawstor::RingBuf<Event*> _cqes;

        std::shared_ptr<Session> _get_session(int fd);

    public:
        static const std::string& engine_name();
        static void setup_fd(int fd);

        Queue(unsigned int depth):
            rawstor::io::Queue(depth),
            _cqes(depth)
        {}

        void read(
            int fd,
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void readv(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void pread(
            int fd,
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        void preadv(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        void write(
            int fd,
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void writev(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb);

        void pwrite(
            int fd,
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        void pwritev(
            int fd,
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb);

        RawstorIOEvent* wait_event(unsigned int timeout);

        void release_event(RawstorIOEvent *event) noexcept;
};


}}} // rawstor::io::poll


#endif // RAWSTORIO_POLL_QUEUE_HPP
