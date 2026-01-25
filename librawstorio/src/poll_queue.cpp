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
Queue::poll(int fd, std::unique_ptr<rawstor::io::Task> t, unsigned int mask) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollOneshot> event =
        std::make_unique<EventSimplexPollOneshot>(
            *this, fd, std::move(t), mask
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.poll(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::poll_multishot(
    int fd, std::unique_ptr<rawstor::io::Task> t, unsigned int mask
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollMultishot> event =
        std::make_unique<EventSimplexPollMultishot>(
            *this, fd, std::move(t), mask
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.poll(std::move(event));
    return ret;
}

rawstor::io::Event*
Queue::read(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRead>(*this, fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event*
Queue::readv(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorRead>(*this, fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event*
Queue::pread(int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<rawstor::io::poll::EventSimplexScalarPositionalRead>(
            *this, fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::preadv(
    int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorPositionalRead>(
            *this, fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::recv(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, unsigned int flags
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRecv>(
            *this, fd, std::move(t), flags
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::recv_multishot(
    int fd, std::unique_ptr<rawstor::io::TaskVectorExternal> t,
    size_t entry_size, unsigned int entries, unsigned int flags
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexVectorRecvMultishot> event =
        std::make_unique<EventSimplexVectorRecvMultishot>(
            *this, fd, std::move(t), entry_size, entries, flags
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::recvmsg(
    int fd, std::unique_ptr<rawstor::io::TaskMessage> t, unsigned int flags
) {
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexMessageRead>(
            *this, fd, std::move(t), flags
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.read(std::move(event));
    return ret;
}

rawstor::io::Event*
Queue::write(int fd, std::unique_ptr<rawstor::io::TaskScalar> t) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexScalarWrite>(*this, fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event*
Queue::writev(int fd, std::unique_ptr<rawstor::io::TaskVector> t) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventMultiplexVectorWrite>(*this, fd, std::move(t));

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::pwrite(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, off_t offset
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(
            *this, fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::pwritev(
    int fd, std::unique_ptr<rawstor::io::TaskVector> t, off_t offset
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(
            *this, fd, std::move(t), offset
        );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::send(
    int fd, std::unique_ptr<rawstor::io::TaskScalar> t, unsigned int flags
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexScalarSend>(
        *this, fd, std::move(t), flags
    );

    rawstor::io::Event* ret = static_cast<rawstor::io::Event*>(event.get());
    s.write(std::move(event));
    return ret;
}

rawstor::io::Event* Queue::sendmsg(
    int fd, std::unique_ptr<rawstor::io::TaskMessage> t, unsigned int flags
) {
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexMessageWrite>(
        *this, fd, std::move(t), flags
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
            // TODO: here should be just s.push()
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
