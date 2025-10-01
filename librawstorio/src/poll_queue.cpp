#include <rawstorio/poll_queue.hpp>

#include "poll_session.hpp"

#include <rawstorio/poll_event.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>
#include <rawstorstd/socket.h>

#include <poll.h>

#include <algorithm>
#include <vector>

#include <cassert>


namespace rawstor {
namespace io {
namespace poll {


std::shared_ptr<Session> Queue::_get_session(int fd) {
    /**
     * TODO: replace list with map or hash.
     */
    std::list<std::shared_ptr<Session>>::iterator it = std::find_if(
        _sessions.begin(), _sessions.end(),
        [fd](std::shared_ptr<Session> it){return it->fd() == fd;}
    );
    if (it != _sessions.end()) {
        return *it;
    }

    std::shared_ptr<Session> session = Session::create(*this, fd);
    _sessions.push_back(session);

    return session;
}


std::string Queue::engine_name() {
    return "poll";
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
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->read(buf, size, cb, data);
}


void Queue::readv(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->readv(iov, niov, size, cb, data);
}


void Queue::pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->pread(buf, size, offset, cb, data);
}


void Queue::preadv(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->preadv(iov, niov, size, offset, cb, data);
}


void Queue::write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->write(buf, size, cb, data);
}


void Queue::writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->writev(iov, niov, size, cb, data);
}


void Queue::pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->pwrite(buf, size, offset, cb, data);
}


void Queue::pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data)
{
    _get_session(fd)->pwritev(iov, niov, size, offset, cb, data);
}


Event* Queue::wait_event(unsigned int timeout) {
    std::vector<pollfd> fds;
    while (_cqes.empty()) {
        size_t count = _sessions.size();
        if (count == 0) {
            return nullptr;
        }

        fds.resize(count);

        std::list<std::shared_ptr<Session>>::iterator it =
            _sessions.begin();

        size_t i = 0;
        while (it != _sessions.end()) {
            if (!(**it).empty()) {
                fds[i] = {
                    .fd = (**it).fd(),
                    .events = (**it).events(),
                    .revents = 0,
                };
                assert(fds[i].events != 0);
                ++it;
                ++i;
            } else {
                it = _sessions.erase(it);
            }
        }

        if (i == 0) {
            return nullptr;
        }

        rawstor_trace("poll()\n");
        int res = ::poll(fds.data(), _sessions.size(), timeout);
        rawstor_trace("poll(): res = %d\n", res);
        if (res == -1) {
            RAWSTOR_THROW_ERRNO();
        }
        if (res == 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(ETIME);
        }

        for (it = _sessions.begin(), i = 0; it != _sessions.end(); ++it, ++i) {
            if (fds[i].revents & POLLHUP) {
                (**it).process_read(_cqes, true);
                (**it).process_write(_cqes, true);
            } else if (fds[i].revents & POLLIN) {
                (**it).process_read(_cqes, false);
            } else if (fds[i].revents & POLLOUT) {
                (**it).process_write(_cqes, false);
            } else {
                continue;
            }
        }
    }

    return _cqes.pop();
}


void Queue::release_event(Event *event) noexcept {
    delete event;
}


}}} // rawstor::io
