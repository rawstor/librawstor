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
            std::unique_ptr<rawstor::io::TaskScalar> t) = 0;

        virtual void read(
            std::unique_ptr<rawstor::io::TaskVector> t) = 0;

        virtual void read(
            std::unique_ptr<rawstor::io::TaskScalarPositional> t) = 0;

        virtual void read(
            std::unique_ptr<rawstor::io::TaskVectorPositional> t) = 0;

        virtual void write(
            std::unique_ptr<rawstor::io::TaskScalar> t) = 0;

        virtual void write(
            std::unique_ptr<rawstor::io::TaskVector> t) = 0;

        virtual void write(
            std::unique_ptr<rawstor::io::TaskScalarPositional> t) = 0;

        virtual void write(
            std::unique_ptr<rawstor::io::TaskVectorPositional> t) = 0;

        virtual void process_read(RingBuf<Event> &cqes, bool pollhup) = 0;
        virtual void process_write(RingBuf<Event> &cqes, bool pollhup) = 0;
};


}}} // rawstor::io

#endif // RAWSTORIO_SESSION_POLL_HPP
