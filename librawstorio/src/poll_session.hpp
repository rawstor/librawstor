#ifndef RAWSTORIO_POLL_SESSION_HPP
#define RAWSTORIO_POLL_SESSION_HPP

#include "poll_queue.hpp"

#include <rawstorstd/ringbuf.hpp>

#include <memory>

namespace rawstor {
namespace io {
namespace poll {


class Event;


class Session {
    protected:
        Queue &_q;
        int _fd;

    public:
        static std::shared_ptr<Session> create(Queue &q, int fd);

        Session(Queue &q, int fd);
        Session(const Session &) = delete;
        Session(Session &&) = delete;
        virtual ~Session() {}
        Session& operator=(const Session &) = delete;
        Session& operator=(Session &&) = delete;

        inline int fd() const noexcept {
            return _fd;
        }

        virtual short events() const noexcept = 0;
        virtual bool empty() const noexcept = 0;

        virtual void read(
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void readv(
            struct iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void pread(
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void preadv(
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void write(
            void *buf, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void writev(
            struct iovec *iov, unsigned int niov, size_t size,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void pwrite(
            void *buf, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void pwritev(
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            std::unique_ptr<rawstor::io::Callback> cb) = 0;

        virtual void process_read(RingBuf<Event*> &cqes, bool pollhup) = 0;
        virtual void process_write(RingBuf<Event*> &cqes, bool pollhup) = 0;
};


}}} // rawstor::io

#endif // RAWSTORIO_SESSION_POLL_HPP
