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
#include <cstring>

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

    std::shared_ptr<Session> session = std::make_shared<Session>(fd, depth());
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
        if (res == -EOPNOTSUPP) {
            rawstor_warning(
                "Failed to set IPPROTO_TCP/TCP_NODELAY for descriptor %d: "
                "%s\n",
                fd, strerror(-res)
            );
        } else {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }
}

rawstor::io::Event*
Queue::poll(int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollOneshot> event =
        std::make_unique<EventSimplexPollOneshot>(
            *this, fd, mask, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.poll(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::poll_multishot(
    int fd, unsigned int mask, std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollMultishot> event =
        std::make_unique<EventSimplexPollMultishot>(
            *this, fd, mask, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.poll(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::read(
    int fd, void* buf, size_t size, std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRead>(
            *this, fd, buf, size, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::readv(
    int fd, iovec* iov, unsigned int niov, std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorRead>(
            *this, fd, iov, niov, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::pread(
    int fd, void* buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<rawstor::io::poll::EventSimplexScalarPositionalRead>(
            *this, fd, buf, size, offset, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::preadv(
    int fd, iovec* iov, unsigned int niov, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorPositionalRead>(
            *this, fd, iov, niov, offset, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::recv(
    int fd, void* buf, size_t size, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRecv>(
            *this, fd, buf, size, flags, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::recv_multishot(
    int fd, size_t entry_size, unsigned int entries, unsigned int flags,
    std::unique_ptr<rawstor::io::TaskVectorExternal> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexVectorRecvMultishot> event =
        std::make_unique<EventSimplexVectorRecvMultishot>(
            *this, fd, entry_size, entries, flags, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::recvmsg(
    int fd, msghdr* msg, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexMessageRead>(
            *this, fd, msg, flags, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::write(
    int fd, const void* buf, size_t size, std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventMultiplexScalarWrite>(
        *this, fd, buf, size, std::move(t)
    );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::writev(
    int fd, const iovec* iov, unsigned int niov,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventMultiplexVectorWrite>(
        *this, fd, iov, niov, std::move(t)
    );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::pwrite(
    int fd, const void* buf, size_t size, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(
            *this, fd, buf, size, offset, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(
            *this, fd, iov, niov, offset, std::move(t)
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::send(
    int fd, const void* buf, size_t size, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexScalarSend>(
        *this, fd, buf, size, flags, std::move(t)
    );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::sendmsg(
    int fd, const msghdr* msg, unsigned int flags,
    std::unique_ptr<rawstor::io::Task> t
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexMessageWrite>(
        *this, fd, msg, flags, std::move(t)
    );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
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

    while (!_cqes.empty()) {
        std::unique_ptr<Event> event(_cqes.pop());
        event->dispatch();

        if (event->is_multishot() && !event->error()) {
            if (event->is_poll()) {
                std::unique_ptr<EventSimplexPoll> poll_event(
                    static_cast<EventSimplexPoll*>(event.release())
                );

                Session& s = _get_session(poll_event->fd());
                s.poll(std::move(poll_event));
            } else if (event->is_read()) {
                std::unique_ptr<EventSimplex> simplex_event(
                    static_cast<EventSimplex*>(event.release())
                );

                Session& s = _get_session(simplex_event->fd());
                s.read(std::move(simplex_event));
            } else {
                throw std::runtime_error("Unexpected multishot event");
            }
        }
    }
}

} // namespace poll
} // namespace io
} // namespace rawstor
