#include "poll_queue.hpp"

#include "poll_event.hpp"
#include "poll_session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <poll.h>

#include <algorithm>
#include <vector>

#include <cassert>
#include <cstring>

namespace {

std::string engine_name = "poll";

} // namespace

namespace rawio {
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

void Queue::_wait_timeout(int timeout) {
    while (!_eval_sqes.empty()) {
        std::unique_ptr<EventEval> event = std::move(_eval_sqes.front());
        _eval_sqes.pop_front();

        event->process();
        _cqes.push(std::move(event));
    }

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

        rawstd_trace("poll()\n");
        int res = ::poll(fds.data(), fds.size(), timeout);
        rawstd_trace("poll(): res = %d\n", res);
        if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }
        if (res == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(ETIME);
        }

        for (const pollfd& fd : fds) {
            rawstd_trace("poll(): revents = %d\n", fd.revents);
            std::shared_ptr<Session>& s = _sessions.at(fd.fd);
            s->process(_cqes, fd.revents);
        }
    }

    while (!_cqes.empty()) {
        std::unique_ptr<Event> event(_cqes.pop());
        _current_event = event.get();
        try {
            event->dispatch();
        } catch (...) {
            _current_event = nullptr;
            throw;
        }
        _current_event = nullptr;
        if (event->is_multishot() && !event->error()) {
            if (event->is_poll()) {
                std::unique_ptr<EventSimplexPoll> poll_event(
                    static_cast<EventSimplexPoll*>(event.release())
                );

                Session& s = _get_session(poll_event->fd());
                s.poll(std::move(poll_event));
            } else if (event->is_accept()) {
                std::unique_ptr<EventSimplexAccept> accept_event(
                    static_cast<EventSimplexAccept*>(event.release())
                );

                Session& s = _get_session(accept_event->fd());
                s.accept(std::move(accept_event));
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

void Queue::_eval(std::unique_ptr<EventEval>&& event) {
    _eval_sqes.push_back(std::move(event));
}

const std::string& Queue::engine_name() {
    return ::engine_name;
}

void Queue::setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 4096 * 64 * 4;

    res = rawstd_socket_set_nonblock(fd);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstd_socket_set_snd_bufsize(fd, bufsize);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstd_socket_set_rcv_bufsize(fd, bufsize);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstd_socket_set_nodelay(fd);
    if (res) {
        if (res == -EOPNOTSUPP) {
            rawstd_warning(
                "Failed to set IPPROTO_TCP/TCP_NODELAY for descriptor %d: "
                "%s\n",
                fd, strerror(-res)
            );
        } else {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

rawio::Event* Queue::open(
    const char* path, int flags, mode_t mode, std::function<void(int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "flags = %d, mode = %d\n", flags, mode);

    std::unique_ptr<EventEval> event = std::make_unique<EventEval>(
        *this, trace_event,
        [path, flags, mode]() -> int {
            int res = ::open(path, flags, mode);
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
            return res;
        },
        std::move(cb)
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return ret;
}

rawio::Event* Queue::close(int fd, std::function<void(int)>&& cb) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "%s\n", "");

    std::unique_ptr<EventEval> event = std::make_unique<EventEval>(
        *this, trace_event,
        [fd]() -> int {
            int res = ::close(fd);
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
            return res;
        },
        std::move(cb)
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return ret;
}

rawio::Event*
Queue::poll(int fd, unsigned int mask, std::function<void(int)>&& cb) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollOneshot> event =
        std::make_unique<EventSimplexPollOneshot>(
            *this, fd, mask, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.poll(std::move(event));
    return ret;
}

rawio::Event* Queue::poll_multishot(
    int fd, unsigned int mask, std::function<void(int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollMultishot> event =
        std::make_unique<EventSimplexPollMultishot>(
            *this, fd, mask, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.poll(std::move(event));
    return ret;
}

rawio::Event* Queue::accept(
    int fd, sockaddr* addr, socklen_t* addrlen, std::function<void(int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexAcceptOneshot> event =
        std::make_unique<EventSimplexAcceptOneshot>(
            *this, fd, addr, addrlen, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.accept(std::move(event));
    return ret;
}

rawio::Event* Queue::accept_multishot(int fd, std::function<void(int)>&& cb) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexAcceptMultishot> event =
        std::make_unique<EventSimplexAcceptMultishot>(
            *this, fd, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.accept(std::move(event));
    return ret;
}

rawio::Event* Queue::read(
    int fd, void* buf, size_t size, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRead>(
            *this, fd, buf, size, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::readv(
    int fd, iovec* iov, unsigned int niov, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, niov = %u\n", fd, niov);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorRead>(
            *this, fd, iov, niov, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::pread(
    int fd, void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd\n", fd, size, (intmax_t)offset
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<rawio::poll::EventSimplexScalarPositionalRead>(
            *this, fd, buf, size, offset, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::preadv(
    int fd, iovec* iov, unsigned int niov, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd\n", fd, niov, (intmax_t)offset
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorPositionalRead>(
            *this, fd, iov, niov, offset, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::recv(
    int fd, void* buf, size_t size, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRecv>(
            *this, fd, buf, size, flags, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::recv_multishot(
    int fd, size_t entry_size, unsigned int entries, size_t size,
    unsigned int flags,
    std::function<size_t(const iovec*, unsigned int, size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|',
        "fd = %d, entry_size = %zu, entries = %u, size = %zu, flags = %u\n", fd,
        entry_size, entries, size, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexVectorRecvMultishot> event =
        std::make_unique<EventSimplexVectorRecvMultishot>(
            *this, fd, entry_size, entries, size, flags, trace_event,
            std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::recvmsg(
    int fd, msghdr* msg, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, flags = %u\n", fd,
        (unsigned int)msg->msg_iovlen, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexMessageRead>(
            *this, fd, msg, flags, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawio::Event* Queue::write(
    int fd, const void* buf, size_t size, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventMultiplexScalarWrite>(
        *this, fd, buf, size, trace_event, std::move(cb)
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawio::Event* Queue::writev(
    int fd, const iovec* iov, unsigned int niov,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, niov = %u\n", fd, niov);
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventMultiplexVectorWrite>(
        *this, fd, iov, niov, trace_event, std::move(cb)
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawio::Event* Queue::pwrite(
    int fd, const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd\n", fd, size, (intmax_t)offset
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(
            *this, fd, buf, size, offset, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawio::Event* Queue::pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd\n", fd, niov, (intmax_t)offset
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(
            *this, fd, iov, niov, offset, trace_event, std::move(cb)
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawio::Event* Queue::send(
    int fd, const void* buf, size_t size, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexScalarSend>(
        *this, fd, buf, size, flags, trace_event, std::move(cb)
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawio::Event* Queue::sendmsg(
    int fd, const msghdr* msg, unsigned int flags,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, flags = %u\n", fd,
        (unsigned int)msg->msg_iovlen, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexMessageWrite>(
        *this, fd, msg, flags, trace_event, std::move(cb)
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

void Queue::cancel(rawio::Event* e) {
    for (auto& it : _sessions) {
        if (it.second->cancel(e, _cqes)) {
            return;
        }
    }
    if (_current_event != nullptr && e == _current_event) {
        _current_event->set_error(ECANCELED);
        return;
    }
    RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
}

void Queue::cancel(int fd) {
    auto it = _sessions.find(fd);
    if (it != _sessions.end()) {
        it->second->cancel(_cqes);
        _sessions.erase(it);
    }
}

void Queue::wait() {
    _wait_timeout(-1);
}

void Queue::wait_timeout(unsigned int timeout) {
    _wait_timeout(timeout);
}

} // namespace poll
} // namespace rawio
