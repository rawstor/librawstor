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


} // unnamed


namespace rawstor {
namespace io {
namespace poll {


std::shared_ptr<Session> Queue::_get_session(int fd) {
    /**
     * TODO: replace list with map or hash.
     */
    std::unordered_map<int, std::shared_ptr<Session>>::iterator it =
        _sessions.find(fd);
    if (it != _sessions.end()) {
        return it->second;
    }

    std::shared_ptr<Session> session = Session::create(*this, fd);
    _sessions[fd] = session;

    return session;
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


void Queue::read(
    int fd,
    void *buf, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->read(buf, size, std::move(t));
}


void Queue::readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->readv(iov, niov, size, std::move(t));
}


void Queue::pread(
    int fd, void *buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->pread(buf, size, offset, std::move(t));
}


void Queue::preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->preadv(iov, niov, size, offset, std::move(t));
}


void Queue::write(
    int fd, void *buf, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->write(buf, size, std::move(t));
}


void Queue::writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->writev(iov, niov, size, std::move(t));
}


void Queue::pwrite(
    int fd, void *buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->pwrite(buf, size, offset, std::move(t));
}


void Queue::pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t)
{
    _get_session(fd)->pwritev(iov, niov, size, offset, std::move(t));
}


bool Queue::empty() const noexcept {
    if (!_cqes.empty()) {
        return false;
    }
    for (const auto &it: _sessions) {
        if (!it.second->empty()) {
            return false;
        }
    }
    return true;
}


void Queue::wait(unsigned int timeout) {
    std::vector<pollfd> fds;
    while (_cqes.empty()) {
        if (_sessions.empty()) {
            return;
        }

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

        if (i == 0) {
            return;
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

        for (const pollfd &fd: fds) {
            std::shared_ptr<Session> &s = _sessions[fd.fd];
            if (fd.revents & POLLHUP) {
                s->process_read(_cqes, true);
                s->process_write(_cqes, true);
            } else if (fd.revents & POLLIN) {
                s->process_read(_cqes, false);
            } else if (fd.revents & POLLOUT) {
                s->process_write(_cqes, false);
            } else {
                continue;
            }
        }
    }

    Event *event = _cqes.pop();

    try {
        event->dispatch();
    } catch (...) {
        delete event;
        throw;
    }

    delete event;
}


}}} // rawstor::io
