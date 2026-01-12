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

void Session::_process_multiplex_write(
    std::vector<std::unique_ptr<EventMultiplex>>& events, unsigned int niov,
    rawstor::RingBuf<Event>& cqes
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
                _write_sqes.push(std::move(event));
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

    rawstor_trace("batch writev()\n");
    ssize_t res = ::writev(_fd, iov.data(), iov.size());
    rawstor_trace("batch res = %zd\n", res);

    if (res > 0) {
        for (std::unique_ptr<EventMultiplex>& event : events) {
            res = event->shift(res);
            if (event->completed()) {
                cqes.push(std::move(event));
            } else {
                _write_sqes.push(std::move(event));
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

void Session::_process_read(rawstor::RingBuf<Event>& cqes) {
    if (_read_sqes.empty()) {
        return;
    }

    std::unique_ptr<EventSimplex> event = _read_sqes.pop();
    _process_simplex(std::move(event), cqes);
}

void Session::_process_write(rawstor::RingBuf<Event>& cqes) {
    if (_write_sqes.empty()) {
        return;
    }

    std::vector<std::unique_ptr<EventMultiplex>> events;
    events.reserve(_write_sqes.size());

    unsigned int niov = 0;
    try {
        while (!_write_sqes.empty()) {
            const Event& tail = _write_sqes.tail();
            if (!tail.multiplex()) {
                if (events.empty()) {
                    std::unique_ptr<Event> event = _write_sqes.pop();
                    std::unique_ptr<EventSimplex> sevent(
                        static_cast<EventSimplex*>(event.release())
                    );
                    _process_simplex(std::move(sevent), cqes);
                    return;
                } else {
                    _process_multiplex_write(events, niov, cqes);
                    return;
                }
            } else {
                std::unique_ptr<Event> event = _write_sqes.pop();
                std::unique_ptr<EventMultiplex> mevent(
                    static_cast<EventMultiplex*>(event.release())
                );
                niov += mevent->niov();
                events.push_back(std::move(mevent));
            }
        }
        _process_multiplex_write(events, niov, cqes);
    } catch (...) {
        for (std::unique_ptr<EventMultiplex>& event : events) {
            _write_sqes.push(std::move(event));
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

rawstor::io::Event*
Session::poll(std::unique_ptr<rawstor::io::Task> t, unsigned int mask) {
    std::unique_ptr<EventSimplexPoll> event =
        std::make_unique<EventSimplexPoll>(_q, _fd, std::move(t), mask);

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _poll_sqes.push_back(std::move(event));

    return ret;
}

rawstor::io::Event* Session::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRead>(_q, _fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::readv(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorRead>(_q, _fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::pread(std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    std::unique_ptr<EventSimplex> event =
        std::make_unique<rawstor::io::poll::EventSimplexScalarPositionalRead>(
            _q, _fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::preadv(std::unique_ptr<rawstor::io::TaskVector> t, off_t offset) {
    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorPositionalRead>(
            _q, _fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::recv(std::unique_ptr<rawstor::io::TaskScalar> t, unsigned int flags) {
    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRecv>(_q, _fd, std::move(t), flags);

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::recvmsg(
    std::unique_ptr<rawstor::io::TaskMessage> t, unsigned int flags
) {
    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexMessageRead>(_q, _fd, std::move(t), flags);

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _read_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexScalarWrite>(_q, _fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::writev(std::unique_ptr<rawstor::io::TaskVector> t) {
    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexVectorWrite>(_q, _fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::pwrite(std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(
            _q, _fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::pwritev(std::unique_ptr<rawstor::io::TaskVector> t, off_t offset) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(
            _q, _fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event*
Session::send(std::unique_ptr<rawstor::io::TaskScalar> t, unsigned int flags) {
    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarSend>(_q, _fd, std::move(t), flags);

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());

    _write_sqes.push(std::move(event));

    return ret;
}

rawstor::io::Event* Session::sendmsg(
    std::unique_ptr<rawstor::io::TaskMessage> t, unsigned int flags
) {
    std::unique_ptr<Event> event = std::make_unique<EventSimplexMessageWrite>(
        _q, _fd, std::move(t), flags
    );

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
    rawstor::RingBuf<EventSimplex> read_sqes(_read_sqes.capacity());
    while (!_read_sqes.empty()) {
        std::unique_ptr<EventSimplex> e = _read_sqes.pop();
        if (event == static_cast<rawstor::io::Event*>(e.get())) {
            found = true;

            e->set_error(ECANCELED);
            cqes.push(std::move(e));
        } else {
            read_sqes.push(std::move(e));
        }
    }
    _read_sqes = std::move(read_sqes);
    if (found) {
        return found;
    }

    rawstor::RingBuf<Event> write_sqes(_write_sqes.capacity());
    while (!_write_sqes.empty()) {
        std::unique_ptr<Event> e = _write_sqes.pop();
        if (event == static_cast<rawstor::io::Event*>(e.get())) {
            found = true;

            e->set_error(ECANCELED);
            cqes.push(std::move(e));
        } else {
            write_sqes.push(std::move(e));
        }
    }
    _write_sqes = std::move(write_sqes);

    return found;
}

void Session::process(
    rawstor::RingBuf<rawstor::io::poll::Event>& cqes, short revents
) {
    _process_poll(cqes, revents);
    if (revents & (POLLIN | POLLERR | POLLHUP | POLLNVAL)) {
        _process_read(cqes);
    }
    if (revents & (POLLOUT | POLLERR | POLLHUP | POLLNVAL)) {
        _process_write(cqes);
    }
}

} // namespace poll
} // namespace io
} // namespace rawstor
