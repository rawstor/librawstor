#include "poll_session.hpp"

#include "poll_event.hpp"
#include "poll_queue.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <memory>
#include <vector>

#include <sys/types.h>
#include <sys/uio.h>

#include <poll.h>
#include <unistd.h>

namespace {


class SeekableSession: public rawstor::io::poll::Session {
    private:
        rawstor::RingBuf<rawstor::io::poll::EventP*> _read_sqes;
        rawstor::RingBuf<rawstor::io::poll::EventP*> _write_sqes;

        void _process(
            rawstor::RingBuf<rawstor::io::poll::EventP*> &sqes,
            rawstor::RingBuf<rawstor::io::poll::Event*> &cqes,
            bool write, bool pollhup);

    public:
        SeekableSession(rawstor::io::poll::Queue &q, int fd):
            Session(q, fd),
            _read_sqes(q.depth()),
            _write_sqes(q.depth())
        {}

        ~SeekableSession() {
            while (!_read_sqes.empty()) {
                rawstor::io::poll::EventP *event = _read_sqes.pop();
                delete event;
            }
            while (!_write_sqes.empty()) {
                rawstor::io::poll::EventP *event = _write_sqes.pop();
                delete event;
            }
        }

        short events() const noexcept {
            return
                (_read_sqes.empty() ? 0 : POLLIN) |
                (_write_sqes.empty() ? 0 : POLLOUT);
        }

        bool empty() const noexcept {
            return _read_sqes.empty() && _write_sqes.empty();
        }

        void read(std::unique_ptr<rawstor::io::TaskScalar>) {
            throw std::runtime_error(
                "method not allowed for seekable session");
        }

        void read(std::unique_ptr<rawstor::io::TaskVector>) {
            throw std::runtime_error(
                "method not allowed for seekable session");
        }

        void read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
            std::unique_ptr<rawstor::io::poll::EventP> event =
                std::make_unique<rawstor::io::poll::EventP>(
                    _q, _fd, std::move(t));

            _read_sqes.push(event.get());

            event.release();
        }

        void read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
            std::unique_ptr<rawstor::io::poll::EventP> event =
                std::make_unique<rawstor::io::poll::EventP>(
                    _q, _fd, std::move(t));

            _read_sqes.push(event.get());

            event.release();
        }

        void write(std::unique_ptr<rawstor::io::TaskScalar>) {
            throw std::runtime_error(
                "method not allowed for seekable session");
        }

        void write(std::unique_ptr<rawstor::io::TaskVector>) {
            throw std::runtime_error(
                "method not allowed for seekable session");
        }

        void write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
            std::unique_ptr<rawstor::io::poll::EventP> event =
                std::make_unique<rawstor::io::poll::EventP>(
                    _q, _fd, std::move(t));

            _write_sqes.push(event.get());

            event.release();
        }

        void write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
            std::unique_ptr<rawstor::io::poll::EventP> event =
                std::make_unique<rawstor::io::poll::EventP>(
                    _q, _fd, std::move(t));

            _write_sqes.push(event.get());

            event.release();
        }

        void process_read(
            rawstor::RingBuf<rawstor::io::poll::Event*> &cqes, bool pollhup)
        {
            _process(_read_sqes, cqes, false, pollhup);
        }

        void process_write(
            rawstor::RingBuf<rawstor::io::poll::Event*> &cqes, bool pollhup)
        {
            _process(_write_sqes, cqes, true, pollhup);
        }
};


class UnseekableSession: public rawstor::io::poll::Session {
    private:
        rawstor::RingBuf<rawstor::io::poll::Event*> _read_sqes;
        rawstor::RingBuf<rawstor::io::poll::Event*> _write_sqes;

        void _process(
            rawstor::RingBuf<rawstor::io::poll::Event*> &sqes,
            rawstor::RingBuf<rawstor::io::poll::Event*> &cqes,
            bool write, bool pollhup);

    public:
        UnseekableSession(rawstor::io::poll::Queue &q, int fd):
            Session(q, fd),
            _read_sqes(q.depth()),
            _write_sqes(q.depth())
        {}

        ~UnseekableSession() {
            while (!_read_sqes.empty()) {
                rawstor::io::poll::Event *event = _read_sqes.pop();
                delete event;
            }
            while (!_write_sqes.empty()) {
                rawstor::io::poll::Event *event = _write_sqes.pop();
                delete event;
            }
        }

        short events() const noexcept {
            return
                (_read_sqes.empty() ? 0 : POLLIN) |
                (_write_sqes.empty() ? 0 : POLLOUT);
        }

        bool empty() const noexcept {
            return _read_sqes.empty() && _write_sqes.empty();
        }

        void read(std::unique_ptr<rawstor::io::TaskScalar> t) {
            std::unique_ptr<rawstor::io::poll::Event> event =
                std::make_unique<rawstor::io::poll::Event>(
                    _q, _fd, std::move(t));

            _read_sqes.push(event.get());

            event.release();
        }

        void read(std::unique_ptr<rawstor::io::TaskVector> t) {
            std::unique_ptr<rawstor::io::poll::Event> event =
                std::make_unique<rawstor::io::poll::Event>(
                    _q, _fd, std::move(t));

            _read_sqes.push(event.get());

            event.release();
        }

        void read(std::unique_ptr<rawstor::io::TaskScalarPositional>) {
            throw std::runtime_error(
                "method not allowed for unseekable session");
        }

        void read(std::unique_ptr<rawstor::io::TaskVectorPositional>) {
            throw std::runtime_error(
                "method not allowed for unseekable session");
        }

        void write(std::unique_ptr<rawstor::io::TaskScalar> t) {
            std::unique_ptr<rawstor::io::poll::Event> event =
                std::make_unique<rawstor::io::poll::Event>(
                    _q, _fd, std::move(t));

            _write_sqes.push(event.get());

            event.release();
        }

        void write(std::unique_ptr<rawstor::io::TaskVector> t) {
            std::unique_ptr<rawstor::io::poll::Event> event =
                std::make_unique<rawstor::io::poll::Event>(
                    _q, _fd, std::move(t));

            _write_sqes.push(event.get());

            event.release();
        }

        void write(std::unique_ptr<rawstor::io::TaskScalarPositional>) {
            throw std::runtime_error(
                "method not allowed for unseekable session");
        }

        void write(std::unique_ptr<rawstor::io::TaskVectorPositional>) {
            throw std::runtime_error(
                "method not allowed for unseekable session");
        }

        void process_read(
            rawstor::RingBuf<rawstor::io::poll::Event*> &cqes, bool pollhup)
        {
            _process(_read_sqes, cqes, false, pollhup);
        }

        void process_write(
            rawstor::RingBuf<rawstor::io::poll::Event*> &cqes, bool pollhup)
        {
            _process(_write_sqes, cqes, true, pollhup);
        }
};


bool is_seekable(int fd) {
    if (::lseek(fd, 0, SEEK_CUR) == -1) {
        int error = errno;
        errno = 0;
        if (error == ESPIPE) {
            return false;
        }
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    return true;
}


void SeekableSession::_process(
    rawstor::RingBuf<rawstor::io::poll::EventP*> &sqes,
    rawstor::RingBuf<rawstor::io::poll::Event*> &cqes,
    bool write, bool pollhup)
{
    if (sqes.empty()) {
        return;
    }

    rawstor::io::poll::EventP *event = sqes.pop();

    ssize_t res;
    if (write) {
        if (!pollhup) {
#ifdef RAWSTOR_TRACE_EVENTS
            event->trace("pwritev()");
#endif
            res = ::pwritev(_fd, event->iov(), event->niov(), event->offset());
        } else {
            res = -1;
            errno = ECONNRESET;
        }
    } else {
#ifdef RAWSTOR_TRACE_EVENTS
        event->trace("preadv()");
#endif
        res = ::preadv(_fd, event->iov(), event->niov(), event->offset());
    }

    if (res > 0) {
        res = event->shift(res);
        if (event->completed()) {
            cqes.push(event);
        } else {
#ifdef RAWSTOR_TRACE_EVENTS
            event->trace("partial");
#endif
            sqes.push(event);
        }
    } else if (res == 0) {
        cqes.push(event);
    } else {
        int error = errno;
        errno = 0;
        event->set_error(error);
        cqes.push(event);
    }
}


void UnseekableSession::_process(
    rawstor::RingBuf<rawstor::io::poll::Event*> &sqes,
    rawstor::RingBuf<rawstor::io::poll::Event*> &cqes,
    bool write, bool pollhup)
{
    if (sqes.empty()) {
        return;
    }

    std::vector<rawstor::io::poll::Event*> events;
    events.reserve(sqes.size());

    unsigned int niov = 0;
    try {
        while (!sqes.empty()) {
            rawstor::io::poll::Event *event = sqes.pop();
            events.push_back(event);
            niov += event->niov();
        }

        std::vector<iovec> iov;
        iov.reserve(niov);
        for (rawstor::io::poll::Event *event: events) {
#ifdef RAWSTOR_TRACE_EVENTS
            event->trace("add to bulk");
#endif
            event->add_iov(iov);
        }

        ssize_t res;
        if (write) {
            if (!pollhup) {
#ifdef RAWSTOR_TRACE_EVENTS
                rawstor_trace("bulk writev()\n");
#endif
                res = ::writev(_fd, iov.data(), iov.size());
            } else {
                res = -1;
                errno = ECONNRESET;
            }
        } else {
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace("bulk readv()\n");
#endif
            res = ::readv(_fd, iov.data(), iov.size());
        }

#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace("bulk res = %zd\n", res);
#endif
        if (res > 0) {
            for (rawstor::io::poll::Event *event: events) {
                res = event->shift(res);
                if (event->completed()) {
                    cqes.push(event);
                } else {
#ifdef RAWSTOR_TRACE_EVENTS
                    event->trace("partial");
#endif
                    sqes.push(event);
                }
            }
        } else if (res == 0) {
            for (rawstor::io::poll::Event *event: events) {
                cqes.push(event);
            }
        } else {
            int error = errno;
            errno = 0;
            for (rawstor::io::poll::Event *event: events) {
                event->set_error(error);
                cqes.push(event);
            }
        }
    } catch (...) {
        for (rawstor::io::poll::Event *event: events) {
            sqes.push(event);
        }
        throw;
    }
}


} // unnamed

namespace rawstor {
namespace io {
namespace poll {


Session::Session(Queue &q, int fd):
    _q(q),
    _fd(fd)
{}


std::shared_ptr<Session> Session::create(Queue &q, int fd) {
    if (is_seekable(fd)) {
        return std::make_shared<SeekableSession>(q, fd);
    }
    return std::make_shared<UnseekableSession>(q, fd);
}


}}} // rawstor::io
