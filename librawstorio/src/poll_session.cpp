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

namespace rawstor {
namespace io {
namespace poll {


Session::Session(Queue &q, int fd):
    _q(q),
    _fd(fd),
    _read_sqes(q.depth()),
    _write_sqes(q.depth())
{}


void Session::_process_simplex(
    std::unique_ptr<EventSimplex> event,
    rawstor::RingBuf<Event> &cqes,
    bool write, bool pollhup)
{
    if (write) {
        if (!pollhup) {
            event->process();
        } else {
            event->set_error(ECONNRESET);
        }
    } else {
        event->process();
    }

    cqes.push(std::move(event));
}


void Session::_process_multiplex(
    std::vector<std::unique_ptr<EventMultiplex>> &events,
    unsigned int niov,
    rawstor::RingBuf<Event> &sqes,
    rawstor::RingBuf<Event> &cqes,
    bool write, bool pollhup)
{
    if (events.size() == 1) {
#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace("single event in batch\n");
#endif
        std::unique_ptr<EventMultiplex> event(events.front().release());
        event->process();
        if (event->completed()) {
            cqes.push(std::move(event));
        } else {
            sqes.push(std::move(event));
        }
        events.clear();
        return;
    }

    std::vector<iovec> iov;
    iov.reserve(niov);
    for (std::unique_ptr<EventMultiplex> &event: events) {
        event->add_to_batch(iov);
    }

    ssize_t res;
    if (write) {
        if (!pollhup) {
#ifdef RAWSTOR_TRACE_EVENTS
            rawstor_trace("batch writev()\n");
#endif
            res = ::writev(_fd, iov.data(), iov.size());
        } else {
            res = -1;
            errno = ECONNRESET;
        }
    } else {
#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace("batch readv()\n");
#endif
        res = ::readv(_fd, iov.data(), iov.size());
    }
#ifdef RAWSTOR_TRACE_EVENTS
    rawstor_trace("batch res = %zd\n", res);
#endif

    if (res > 0) {
        for (std::unique_ptr<EventMultiplex> &event: events) {
            res = event->shift(res);
            if (event->completed()) {
                cqes.push(std::move(event));
            } else {
                sqes.push(std::move(event));
            }
        }
    } else if (res == 0) {
        for (std::unique_ptr<EventMultiplex> &event: events) {
            cqes.push(std::move(event));
        }
    } else {
        int error = errno;
        errno = 0;
        for (std::unique_ptr<EventMultiplex> &event: events) {
            event->set_error(error);
            cqes.push(std::move(event));
        }
    }
    events.clear();
}


void Session::_process(
    rawstor::RingBuf<Event> &sqes,
    rawstor::RingBuf<Event> &cqes,
    bool write, bool pollhup)
{
    if (sqes.empty()) {
        return;
    }

    std::vector<std::unique_ptr<EventMultiplex>> events;
    events.reserve(sqes.size());

    unsigned int niov = 0;
    try {
        while (!sqes.empty()) {
            const Event &tail = sqes.tail();
            if (!tail.multiplex()) {
                if (events.empty()) {
                    std::unique_ptr<Event> event = sqes.pop();
                    std::unique_ptr<EventSimplex> sevent(
                        static_cast<EventSimplex*>(event.release()));
                    _process_simplex(std::move(sevent), cqes, write, pollhup);
                    return;
                } else {
                    _process_multiplex(events, niov, sqes, cqes, write, pollhup);
                    return;
                }
            } else {
                std::unique_ptr<Event> event = sqes.pop();
                std::unique_ptr<EventMultiplex> mevent(
                    static_cast<EventMultiplex*>(event.release()));
                niov += mevent->niov();
                events.push_back(std::move(mevent));
            }
        }
        _process_multiplex(events, niov, sqes, cqes, write, pollhup);
    } catch (...) {
        for (std::unique_ptr<EventMultiplex> &event: events) {
            sqes.push(std::move(event));
        }
        throw;
    }
}


void Session::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexScalarRead>(
            _q, std::move(t));

    _read_sqes.push(std::move(event));
}


void Session::read(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexVectorRead>(
            _q, std::move(t));

    _read_sqes.push(std::move(event));
}


void Session::read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<rawstor::io::poll::Event> event =
        std::make_unique<rawstor::io::poll::EventSimplexScalarPositionalRead>(
            _q, std::move(t));

    _read_sqes.push(std::move(event));
}


void Session::read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalRead>(
            _q, std::move(t));

    _read_sqes.push(std::move(event));
}


void Session::read(std::unique_ptr<rawstor::io::TaskMessage> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexMessageRead>(
            _q, std::move(t));

    _read_sqes.push(std::move(event));
}


void Session::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexScalarWrite>(
            _q, std::move(t));

    _write_sqes.push(std::move(event));
}


void Session::write(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexVectorWrite>(
            _q, std::move(t));

    _write_sqes.push(std::move(event));
}


void Session::write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(
            _q, std::move(t));

    _write_sqes.push(std::move(event));
}


void Session::write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(
            _q, std::move(t));

    _write_sqes.push(std::move(event));
}


void Session::write(std::unique_ptr<rawstor::io::TaskMessage> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexMessageWrite>(
            _q, std::move(t));

    _write_sqes.push(std::move(event));
}


void Session::process_read(
    rawstor::RingBuf<rawstor::io::poll::Event> &cqes,
    bool pollhup)
{
    _process(_read_sqes, cqes, false, pollhup);
}


void Session::process_write(
    rawstor::RingBuf<rawstor::io::poll::Event> &cqes,
    bool pollhup)
{
    _process(_write_sqes, cqes, true, pollhup);
}


}}} // rawstor::io::poll
