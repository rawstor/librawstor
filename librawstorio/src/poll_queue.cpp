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

rawstor::io::Event*
Queue::poll(int fd, std::unique_ptr<rawstor::io::Task> t, int flags) {
    Session& s = _get_session(fd);
    return s.poll(std::move(t), flags);
}

rawstor::io::Event*
Queue::read(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    Session& s = _get_session(fd);
    return s.read(std::move(t));
}

rawstor::io::Event*
Queue::readv(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    Session& s = _get_session(fd);
    return s.readv(std::move(t));
}

rawstor::io::Event*
Queue::pread(int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    Session& s = _get_session(fd);
    return s.pread(std::move(t), offset);
}

rawstor::io::Event* Queue::preadv(
    int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
) {
    Session& s = _get_session(fd);
    return s.preadv(std::move(t), offset);
}

rawstor::io::Event*
Queue::recvmsg(int fd, std::unique_ptr<rawstor::io::TaskMessage> t, int flags) {
    Session& s = _get_session(fd);
    return s.recvmsg(std::move(t), flags);
}

rawstor::io::Event*
Queue::write(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    Session& s = _get_session(fd);
    return s.write(std::move(t));
}

rawstor::io::Event*
Queue::writev(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    Session& s = _get_session(fd);
    return s.writev(std::move(t));
}

rawstor::io::Event* Queue::pwrite(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset
) {
    Session& s = _get_session(fd);
    return s.pwrite(std::move(t), offset);
}

rawstor::io::Event* Queue::pwritev(
    int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
) {
    Session& s = _get_session(fd);
    return s.pwritev(std::move(t), offset);
}

rawstor::io::Event*
Queue::sendmsg(int fd, std::unique_ptr<rawstor::io::TaskMessage> t, int flags) {
    Session& s = _get_session(fd);
    return s.sendmsg(std::move(t), flags);
}

void Queue::cancel(rawstor::io::Event* e) {
    for (auto& it : _sessions) {
        if (it.second->cancel(e, _cqes)) {
            return;
        }
    }
    RAWSTOR_THROW_SYSTEM_ERROR(ENOENT);
}

bool Queue::empty() const noexcept {
    if (!_cqes.empty()) {
        return false;
    }
    for (const auto& it : _sessions) {
        if (!it.second->empty()) {
            return false;
        }
    }
    return true;
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
