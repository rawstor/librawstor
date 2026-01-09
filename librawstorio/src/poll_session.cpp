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

Session::Session(Queue& q, int fd) :
    _q(q),
    _fd(fd),
    _read_sqes(q.depth()),
    _write_sqes(q.depth()) {
}

void Session::_process_poll(rawstor::RingBuf<Event>& cqes, short revents) {
    for (auto it = _poll_sqes.begin(); it != _poll_sqes.end();) {
        if (((*it)->mask() | POLLERR | POLLHUP | POLLNVAL) & revents) {
            std::unique_ptr<EventSimplexPoll> event = std::move(*it);
            it = _poll_sqes.erase(it);

            event->set_result(revents);
            event->process();
            cqes.push(std::move(event));
        } else {
            ++it;
        }
    }
}

void Session::_process_simplex(
    std::unique_ptr<EventSimplex> event, rawstor::RingBuf<Event>& cqes
) {
    event->process();
    cqes.push(std::move(event));
}

void Session::_process_multiplex(
    std::vector<std::unique_ptr<EventMultiplex>>& events, unsigned int niov,
    rawstor::RingBuf<Event>& sqes, rawstor::RingBuf<Event>& cqes, bool write
) {
    if (events.size() == 1) {
#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace("single event in batch\n");
#endif
        std::unique_ptr<EventMultiplex> event(events.front().release());
        ssize_t res;
        res = event->process();
        if (res > 0) {
            if (event->completed()) {
                cqes.push(std::move(event));
            } else {
                sqes.push(std::move(event));
            }
        } else if (res == 0) {
            cqes.push(std::move(event));
        } else {
            cqes.push(std::move(event));
        }
        events.clear();
        return;
    }

    std::vector<iovec> iov;
    iov.reserve(niov);
    for (std::unique_ptr<EventMultiplex>& event : events) {
        event->add_to_batch(iov);
    }

    ssize_t res;
    if (write) {
#ifdef RAWSTOR_TRACE_EVENTS
        rawstor_trace("batch writev()\n");
#endif
        res = ::writev(_fd, iov.data(), iov.size());
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
        for (std::unique_ptr<EventMultiplex>& event : events) {
            res = event->shift(res);
            if (event->completed()) {
                cqes.push(std::move(event));
            } else {
                sqes.push(std::move(event));
            }
        }
    } else if (res == 0) {
        for (std::unique_ptr<EventMultiplex>& event : events) {
            cqes.push(std::move(event));
        }
    } else {
        int error = errno;
        errno = 0;
        for (std::unique_ptr<EventMultiplex>& event : events) {
            event->set_error(error);
            cqes.push(std::move(event));
        }
    }
    events.clear();
}

void Session::_process(
    rawstor::RingBuf<Event>& sqes, rawstor::RingBuf<Event>& cqes, bool write
) {
    if (sqes.empty()) {
        return;
    }

    std::vector<std::unique_ptr<EventMultiplex>> events;
    events.reserve(sqes.size());

    unsigned int niov = 0;
    try {
        while (!sqes.empty()) {
            const Event& tail = sqes.tail();
            if (!tail.multiplex()) {
                if (events.empty()) {
                    std::unique_ptr<Event> event = sqes.pop();
                    std::unique_ptr<EventSimplex> sevent(
                        static_cast<EventSimplex*>(event.release())
                    );
                    _process_simplex(std::move(sevent), cqes);
                    return;
                } else {
                    _process_multiplex(events, niov, sqes, cqes, write);
                    return;
                }
            } else {
                std::unique_ptr<Event> event = sqes.pop();
                std::unique_ptr<EventMultiplex> mevent(
                    static_cast<EventMultiplex*>(event.release())
                );
                niov += mevent->niov();
                events.push_back(std::move(mevent));
            }
        }
        _process_multiplex(events, niov, sqes, cqes, write);
    } catch (...) {
        for (std::unique_ptr<EventMultiplex>& event : events) {
            sqes.push(std::move(event));
        }
        throw;
    }
}

short Session::events() const noexcept {
    short ret = 0;
    for (const auto& it : _poll_sqes) {
        ret |= it->mask();
    }
    if (!_read_sqes.empty()) {
        ret |= POLLIN;
    }
    if (!_write_sqes.empty()) {
        ret |= POLLOUT;
    }
    return ret;
}

rawstor::io::Event* Session::poll(std::unique_ptr<rawstor::io::TaskPoll> t) {
    std::unique_ptr<EventSimplexPoll> event =
        std::make_unique<EventSimplexPoll>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _poll_sqes.push_back(std::move(event));

    return ret;
}

rawstor::io::Event* Session::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexScalarRead>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::read(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexVectorRead>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<rawstor::io::poll::Event> event =
        std::make_unique<rawstor::io::poll::EventSimplexScalarPositionalRead>(
            _q, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalRead>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::read(std::unique_ptr<rawstor::io::TaskMessage> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexMessageRead>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexScalarWrite>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::write(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexVectorWrite>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::write(std::unique_ptr<rawstor::io::TaskMessage> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexMessageWrite>(_q, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

bool Session::cancel(rawstor::io::Event* event, rawstor::RingBuf<Event>& cqes) {
    for (std::list<std::unique_ptr<EventSimplexPoll>>::iterator it =
             _poll_sqes.begin();
         it != _poll_sqes.end(); ++it) {
        if (event == static_cast<rawstor::io::Event*>(it->get())) {
            std::unique_ptr<EventSimplexPoll> e = std::move(*it);
            _poll_sqes.erase(it);

            e->set_error(ECANCELED);
            cqes.push(std::move(e));
            return true;
        }
    }

    bool found = false;
    rawstor::RingBuf<Event> read_sqes(_read_sqes.capacity());
    while(!_read_sqes.empty()) {
        std::unique_ptr<Event> e = _read_sqes.pop();
        if (event == static_cast<rawstor::io::Event*>(e.get())) {
            found = true;

            e->set_error(ECANCELED);
            cqes.push(std::move(e));
        } else {
            read_sqes.push(std::move(e));
        }
    }
    _read_sqes = std::move(read_sqes);
    return found;
}

void Session::process(
    rawstor::RingBuf<rawstor::io::poll::Event>& cqes, short revents
) {
    _process_poll(cqes, revents);
    if (revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
        _process(_read_sqes, cqes, false);
    }
    if (revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
        _process(_write_sqes, cqes, true);
    }
}

} // namespace poll
} // namespace io
} // namespace rawstor
