#include "poll_queue.hpp"

#include "poll_event.hpp"
#include "poll_session.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/socket.h>

#include <poll.h>

#include <algorithm>
#include <vector>

#include <cassert>

namespace {

std::string engine_name = "poll";

} // namespace

namespace rawstor {
namespace io {
namespace poll {

Session& Queue::_get_session(int fd) {
    std::unordered_map<int, std::shared_ptr<Session>>::iterator it =
        _sessions.find(fd);
    if (it != _sessions.end()) {
        return *it->second;
    }

    std::shared_ptr<Session> session = std::make_shared<Session>(*this, fd);
    _sessions[fd] = session;

    return *session;
}

const std::string& Queue::engine_name() {
    return ::engine_name;
}

void Queue::setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 4096 * 64 * 4;

    res = rawstor_socket_set_nonblock(fd);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_snd_bufsize(fd, bufsize);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_rcv_bufsize(fd, bufsize);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstor_socket_set_nodelay(fd);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

rawstor::io::Event* Queue::poll(std::unique_ptr<rawstor::io::TaskPoll> t) {
    Session& s = _get_session(t->fd());
    return s.poll(std::move(t));
}

rawstor::io::Event* Queue::read(std::unique_ptr<rawstor::io::TaskScalar> t) {
    Session& s = _get_session(t->fd());
    return s.read(std::move(t));
}

rawstor::io::Event* Queue::read(std::unique_ptr<rawstor::io::TaskVector> t) {
    Session& s = _get_session(t->fd());
    return s.read(std::move(t));
}

rawstor::io::Event*
Queue::read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    Session& s = _get_session(t->fd());
    return s.read(std::move(t));
}

rawstor::io::Event*
Queue::read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    Session& s = _get_session(t->fd());
    return s.read(std::move(t));
}

rawstor::io::Event* Queue::read(std::unique_ptr<rawstor::io::TaskMessage> t) {
    Session& s = _get_session(t->fd());
    return s.read(std::move(t));
}

rawstor::io::Event* Queue::write(std::unique_ptr<rawstor::io::TaskScalar> t) {
    Session& s = _get_session(t->fd());
    return s.write(std::move(t));
}

rawstor::io::Event* Queue::write(std::unique_ptr<rawstor::io::TaskVector> t) {
    Session& s = _get_session(t->fd());
    return s.write(std::move(t));
}

rawstor::io::Event*
Queue::write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) {
    Session& s = _get_session(t->fd());
    return s.write(std::move(t));
}

rawstor::io::Event*
Queue::write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) {
    Session& s = _get_session(t->fd());
    return s.write(std::move(t));
}

rawstor::io::Event* Queue::write(std::unique_ptr<rawstor::io::TaskMessage> t) {
    Session& s = _get_session(t->fd());
    return s.write(std::move(t));
}

void Queue::cancel(rawstor::io::Event* e) {
    for (auto& it : _sessions) {
        if (it.second->cancel(e, _cqes)) {
            return;
        }
    }
    RAWSTOR_THROW_SYSTEM_ERROR(ENOENT);
}

void Queue::wait(unsigned int timeout) {
    while (_cqes.empty()) {
        std::vector<pollfd> fds;
        fds.reserve(_sessions.size());

        std::unordered_map<int, std::shared_ptr<Session>>::iterator it =
            _sessions.begin();

        size_t i = 0;
        while (it != _sessions.end()) {
            if (!it->second->empty()) {
                fds.push_back({
                    .fd = it->second->fd(),
                    .events = it->second->events(),
                    .revents = 0,
                });
                assert(fds[i].events != 0);
                ++it;
                ++i;
            } else {
                it = _sessions.erase(it);
            }
        }

        rawstor_trace("poll()\n");
        int res = ::poll(fds.data(), fds.size(), timeout);
        rawstor_trace("poll(): res = %d\n", res);
        if (res == -1) {
            RAWSTOR_THROW_ERRNO();
        }
        if (res == 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(ETIME);
        }

        for (const pollfd& fd : fds) {
            rawstor_trace("poll(): revents = %d\n", fd.revents);
            std::shared_ptr<Session>& s = _sessions.at(fd.fd);
            s->process(_cqes, fd.revents);
        }
    }

    std::unique_ptr<Event> event(_cqes.pop());
    event->dispatch();
}

} // namespace poll
} // namespace io
} // namespace rawstor
