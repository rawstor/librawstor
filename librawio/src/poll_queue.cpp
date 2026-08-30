#include "poll_queue.hpp"

#include "poll_event.hpp"
#include "poll_session.hpp"
#include "poll_stream_backend.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <poll.h>

#include <algorithm>
#include <chrono>
#include <vector>

#include <cassert>
#include <cstring>
#include <fcntl.h>

namespace {

std::string engine_name = "poll";

} // namespace

namespace rawio {
namespace poll {

// Cancels and drains every still-registered session one at a time, rather
// than cancelling them all up front: Session::cancel(cqes) pushes
// straight into the bounded _cqes ring (the same thing Queue::cancel(fd)'s
// eval callback does live), and doing that for every session before any
// of them get dispatched could overflow it (ENOBUFS) if the combined
// pending-event count across sessions exceeds depth. Draining via
// wait_timeout(0) after each session's cancel() keeps at most one
// session's worth of cancelled events in _cqes at a time. Safe to do now
// that Object/Connection/Session's internals are genuinely
// co_await-composed on the shared Queue instead of nesting a private,
// throwaway one's own synchronous pump inside this Queue's own dispatch
// (the reentrancy hazard that made an earlier version of this destructor
// corrupt memory -- see ref/librawio-coroutines' history).
Queue::~Queue() {
    try {
        while (!_sessions.empty()) {
            std::unordered_map<int, std::shared_ptr<Session>>::iterator it =
                _sessions.begin();
            it->second->cancel(_cqes);
            _sessions.erase(it);

            while (true) {
                try {
                    wait_timeout(0);
                } catch (const std::system_error& e) {
                    if (e.code().value() == ETIME) {
                        // Nothing left to reap -- the drain above is done.
                        break;
                    }
                    if (e.code().value() != ECANCELED) {
                        // Logged, not thrown further -- the loop below
                        // just stops draining this session and control
                        // moves on to the next one (or returns from the
                        // destructor) normally either way, so this
                        // doesn't rise to the level of an error.
                        rawstd_warning("Failed to wait: %s\n", e.what());
                        break;
                    }
                    // ECANCELED: one of the events this session's own
                    // cancel(_cqes) call above pushed just got dispatched --
                    // exactly what was asked for, not a failure. Dispatch
                    // stops at the first completion that throws, so there
                    // may be more of this same session's cancelled events
                    // still sitting in _cqes; keep draining instead of
                    // stopping here (see this destructor's own doc comment
                    // for why more than one is expected).
                } catch (const std::exception& e) {
                    rawstd_warning("Failed to wait: %s\n", e.what());
                    break;
                }
            }
        }

        // _timers never goes through _cqes (see its own doc comment), so
        // there's nothing to drain via wait_timeout(0) here -- dispatching
        // (resolve_one_shot(), via set_error()+dispatch()) is itself the
        // whole cancellation, same as EventEval's synchronous dispatch.
        while (!_timers.empty()) {
            std::unique_ptr<EventTimer> t = std::move(_timers.front());
            _timers.pop_front();

            t->set_error(ECANCELED);
            _current_event = t.get();
            try {
                t->dispatch();
                rawstd::DetachedTask::rethrow_if_pending();
            } catch (...) {
                _current_event = nullptr;
                throw;
            }
            _current_event = nullptr;
        }
    } catch (const std::exception& e) {
        rawstd_error("Failed to cancel sessions: %s\n", e.what());
    }
}

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

bool Queue::_reap_timers() {
    bool any = false;
    std::chrono::steady_clock::time_point now =
        std::chrono::steady_clock::now();

    while (!_timers.empty() && _timers.front()->deadline() <= now) {
        std::unique_ptr<EventTimer> event = std::move(_timers.front());
        _timers.pop_front();

        any = true;
        _current_event = event.get();
        try {
            event->dispatch();
            rawstd::DetachedTask::rethrow_if_pending();
        } catch (...) {
            _current_event = nullptr;
            throw;
        }
        _current_event = nullptr;
    }

    return any;
}

void Queue::_wait_timeout(int msec) {
    /*
     * One generation per _wait_timeout() call, covering however this
     * particular batch of _cqes got filled -- a fresh ::poll() readiness
     * pass below, or events already sitting in _cqes from cancel()/eval()
     * that bypass it entirely. Either way, everything dispatched during
     * this call is "the same batch" for de-duplication purposes.
     */
    ++_dispatch_generation;

    // Dispatched immediately, one at a time, rather than deferred through
    // _cqes like everything else: _cqes's capacity is sized to `depth`
    // (the number of real I/O ops that can be in flight at once), but an
    // eval's own callback can independently push into _cqes as a side
    // effect (cancel()'s does, force-completing the target it found) --
    // pushing the EventEval itself in *addition* to that, into the same
    // bounded ring, could overflow it (ENOBUFS) even though nothing is
    // actually over its real in-flight-ops capacity. An EventEval isn't
    // an I/O op competing for a `depth` slot, so it doesn't need one. This
    // also means a burst of N evals queued before the next wait_timeout()
    // (e.g. cancelling everything in flight during shutdown) can never
    // overflow _cqes, since none of them consume a slot just to be
    // dispatched.
    //
    // Processing at least one eval already counts as this call having made
    // progress -- skip the blocking poll() phase below even if none of
    // them happened to also leave anything in _cqes (e.g. open()/close(),
    // whose callbacks don't touch _cqes at all), the same way a non-empty
    // _cqes would have skipped it.
    bool evaluated = !_eval_sqes.empty();
    while (!_eval_sqes.empty()) {
        std::unique_ptr<EventEval> event = std::move(_eval_sqes.front());
        _eval_sqes.pop_front();

        event->process();
        _current_event = event.get();
        try {
            event->dispatch();
            rawstd::DetachedTask::rethrow_if_pending();
        } catch (...) {
            _current_event = nullptr;
            throw;
        }
        _current_event = nullptr;
    }

    // A timer already due (e.g. a caller spinning wait_timeout(0), or
    // several timeout()s queued back-to-back before the next
    // wait()/wait_timeout() call) counts as progress exactly like a
    // drained eval above -- resolves without ever entering ::poll() below.
    if (_reap_timers()) {
        evaluated = true;
    }

    while (_cqes.empty() && !evaluated) {
        // The timeout ::poll() itself gets is `msec`, clamped down to
        // whatever's left until the soonest pending timer's deadline (if
        // that's sooner) -- rounded up so ::poll() never returns a hair
        // before that deadline. `clamped` records whether this round's
        // budget is genuinely the caller's own or just this timer's --
        // needed below to tell a caller's real ETIME apart from ::poll()
        // simply returning 0 because we cut its own timeout short.
        int poll_msec = msec;
        bool clamped = false;
        if (!_timers.empty()) {
            std::chrono::milliseconds remaining_ms = std::max(
                std::chrono::ceil<std::chrono::milliseconds>(
                    _timers.front()->deadline() -
                    std::chrono::steady_clock::now()
                ),
                std::chrono::milliseconds(0)
            );
            int timer_msec = static_cast<int>(remaining_ms.count());
            if (msec < 0 || timer_msec < msec) {
                poll_msec = timer_msec;
                clamped = true;
            }
        }

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
        int res = ::poll(fds.data(), fds.size(), poll_msec);
        rawstd_trace("poll(): res = %d\n", res);
        if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (_reap_timers()) {
            evaluated = true;
        }

        if (res == 0) {
            // Nothing ready. If evaluated by now (a timer just fired) or
            // this round's budget was our own clamp rather than the
            // caller's, this isn't the caller's timeout expiring -- loop
            // back around and recompute against whatever's left.
            if (evaluated || clamped) {
                continue;
            }
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
            // dispatch() may have resumed a rawstd::DetachedTask that
            // threw -- see DetachedTask's own doc comment for why that
            // can't be delivered by rethrowing directly out of
            // dispatch()/resume() itself, and rethrow_if_pending()'s for
            // why this is one of only two places that need to check.
            rawstd::DetachedTask::rethrow_if_pending();
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

void Queue::_eval(std::unique_ptr<EventEval> event) {
    _eval_sqes.push_back(std::move(event));
}

const std::string& Queue::engine_name() {
    return ::engine_name;
}

void Queue::setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 16 * 1024 * 1024;

    res = rawstd_socket_set_nonblock(fd);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    // No-op on Linux (send()/sendmsg() suppress SIGPIPE per-call via
    // MSG_NOSIGNAL instead); on macOS this is the only way to suppress it,
    // since macOS has no per-call flag equivalent.
    res = rawstd_socket_set_nosigpipe(fd);
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

rawio::Awaitable<int> Queue::open(const char* path, int flags, mode_t mode) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "flags = %d, mode = %d\n", flags, mode);

    std::unique_ptr<EventEval> event = std::make_unique<EventEval>(
        *this, trace_event, [path, flags, mode]() -> int {
            int res = ::open(path, flags, mode);
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
            return res;
        }
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::Awaitable<int> Queue::close(int fd) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "%s\n", "");

    std::unique_ptr<EventEval> event =
        std::make_unique<EventEval>(*this, trace_event, [fd]() -> int {
            int res = ::close(fd);
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
            return res;
        });

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::Awaitable<int> Queue::poll(int fd, unsigned int mask) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexPollOneshot> event =
        std::make_unique<EventSimplexPollOneshot>(*this, fd, mask, trace_event);

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.poll(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::PollStream Queue::poll_multishot(int fd, unsigned int mask) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    Session& s = _get_session(fd);

    auto backend =
        std::make_shared<PollMultishotBackend>(*this, _dispatch_generation);
    std::unique_ptr<EventSimplexPollMultishot> event =
        std::make_unique<EventSimplexPollMultishot>(
            *this, fd, mask, trace_event, backend
        );

    backend->set_event(event.get());
    s.poll(std::move(event));
    return rawio::PollStream(std::move(backend));
}

rawio::Awaitable<int>
Queue::accept(int fd, sockaddr* addr, socklen_t* addrlen) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplexAcceptOneshot> event =
        std::make_unique<EventSimplexAcceptOneshot>(
            *this, fd, addr, addrlen, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.accept(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::AcceptStream Queue::accept_multishot(int fd) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    Session& s = _get_session(fd);

    auto backend =
        std::make_shared<AcceptMultishotBackend>(*this, _dispatch_generation);
    std::unique_ptr<EventSimplexAcceptMultishot> event =
        std::make_unique<EventSimplexAcceptMultishot>(
            *this, fd, trace_event, backend
        );

    backend->set_event(event.get());
    s.accept(std::move(event));
    return rawio::AcceptStream(std::move(backend));
}

rawio::Awaitable<int>
Queue::connect(int fd, const sockaddr* addr, socklen_t addrlen) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);

    std::unique_ptr<EventEval> event = std::make_unique<EventEval>(
        *this, trace_event, [fd, addr, addrlen]() -> int {
            int res = ::connect(fd, addr, addrlen);
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
            return res;
        }
    );
    // The non-blocking ::connect() attempt above resolves this event
    // directly unless it needs a POLLOUT retry (EINPROGRESS/EINTR) -- in
    // that case, whoever ends up co_await-ing this connect() actually
    // gets resumed once the *retry* poll() event resolves, via
    // adopt_attachment() handing this event's pending attachment over to
    // it (submission already happened, so the caller's eventual co_await
    // just attaches to whichever Event object is still holding the
    // pointers by then).
    event->set_on_dispatch([this, fd](Event& e) {
        int connect_result = static_cast<int>(e.result());
        if (connect_result != -EINTR && connect_result != -EINPROGRESS) {
            e.resolve_one_shot_raw(connect_result);
            return;
        }

        Session& s = _get_session(fd);
        std::unique_ptr<EventSimplexPollOneshot> poll_event =
            std::make_unique<EventSimplexPollOneshot>(
                *this, fd, POLLOUT, e.trace_event
            );
        poll_event->adopt_attachment(e);
        poll_event->set_on_dispatch([fd](Event& pe) {
            int poll_result =
                pe.error() ? -pe.error() : static_cast<int>(pe.result());
            if (poll_result == -1) {
                RAWSTD_THROW_ERRNO();
            }
            if (poll_result == 0) {
                pe.resolve_one_shot_raw(-ETIMEDOUT);
                return;
            }
            if (!(poll_result & POLLOUT)) {
                pe.resolve_one_shot_raw(-ENOTCONN);
                return;
            }

            int err = 0;
            socklen_t len = sizeof(err);
            if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &err, &len) < 0) {
                RAWSTD_THROW_ERRNO();
            }
            pe.resolve_one_shot_raw(err != 0 ? -err : 0);
        });
        s.poll(std::move(poll_event));
    });

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::Awaitable<size_t> Queue::read(int fd, void* buf, size_t size) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRead>(
            *this, fd, buf, size, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t> Queue::readv(int fd, iovec* iov, unsigned int niov) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, niov = %u\n", fd, niov);
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorRead>(
            *this, fd, iov, niov, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t>
Queue::pread(int fd, void* buf, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd\n", fd, size, (intmax_t)offset
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<rawio::poll::EventSimplexScalarPositionalRead>(
            *this, fd, buf, size, offset, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t>
Queue::preadv(int fd, iovec* iov, unsigned int niov, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd\n", fd, niov, (intmax_t)offset
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexVectorPositionalRead>(
            *this, fd, iov, niov, offset, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t>
Queue::recv(int fd, void* buf, size_t size, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexScalarRecv>(
            *this, fd, buf, size, flags, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::RecvStream Queue::recv_multishot(
    int fd, size_t entry_size, unsigned int entries, size_t size,
    unsigned int flags
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|',
        "fd = %d, entry_size = %zu, entries = %u, size = %zu, flags = %u\n", fd,
        entry_size, entries, size, flags
    );
    Session& s = _get_session(fd);

    auto backend = std::make_shared<RecvMultishotBackend>(*this, entries);
    std::unique_ptr<EventSimplexVectorRecvMultishot> event =
        std::make_unique<EventSimplexVectorRecvMultishot>(
            *this, fd, entry_size, flags, trace_event, backend
        );

    backend->set_event(event.get());
    s.read(std::move(event));
    return rawio::RecvStream(std::move(backend));
}

rawio::Awaitable<size_t>
Queue::recvmsg(int fd, msghdr* msg, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, flags = %u\n", fd,
        (unsigned int)msg->msg_iovlen, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<EventSimplex> event =
        std::make_unique<EventSimplexMessageRead>(
            *this, fd, msg, flags, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.read(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t> Queue::write(int fd, const void* buf, size_t size) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventMultiplexScalarWrite>(
        *this, fd, buf, size, trace_event
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t>
Queue::writev(int fd, const iovec* iov, unsigned int niov) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, niov = %u\n", fd, niov);
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventMultiplexVectorWrite>(
        *this, fd, iov, niov, trace_event
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t>
Queue::pwrite(int fd, const void* buf, size_t size, off_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd, sync = %d\n", fd, size,
        (intmax_t)offset, sync
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexScalarPositionalWrite>(
            *this, fd, buf, size, offset, sync, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t> Queue::pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd, sync = %d\n", fd, niov,
        (intmax_t)offset, sync
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event =
        std::make_unique<EventSimplexVectorPositionalWrite>(
            *this, fd, iov, niov, offset, sync, trace_event
        );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<int> Queue::fsync(int fd, bool datasync) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, datasync = %d\n", fd, datasync);

    std::unique_ptr<EventEval> event = std::make_unique<EventEval>(
        *this, trace_event, [fd, datasync]() -> int {
            int res;
#if defined(RAWSTD_ON_LINUX)
            res = datasync ? ::fdatasync(fd) : ::fsync(fd);
#elif defined(RAWSTD_ON_MACOS)
            (void)datasync;
            res = ::fcntl(fd, F_FULLFSYNC);
#else
#error "Unexpected platform"
#endif
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
            return res;
        }
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::Awaitable<int>
Queue::fallocate(int fd, int mode, off_t offset, off_t len) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, mode = %d, offset = %jd, len = %jd\n", fd, mode,
        (intmax_t)offset, (intmax_t)len
    );

    std::unique_ptr<EventEval> event = std::make_unique<EventEval>(
        *this, trace_event, [fd, mode, offset, len]() -> int {
            int res;
#if defined(RAWSTD_ON_LINUX)
            res = ::fallocate(fd, mode, offset, len);
            if (res == -1) {
                res = -errno;
                errno = 0;
            }
#elif defined(RAWSTD_ON_MACOS)
            // No macOS equivalent of Linux's mode-flagged fallocate() (hole
            // punch/zero-range/...) -- every caller of this op already
            // treats ENOSYS as "fall back to a portable path" (see
            // blk::Session::discard()/write_zeroes(), src/blk_session.cpp),
            // so this platform just always takes that fallback.
            (void)fd;
            (void)mode;
            (void)offset;
            (void)len;
            res = -ENOSYS;
#else
#error "Unexpected platform"
#endif
            return res;
        }
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<int>(this, ret);
}

rawio::Awaitable<size_t>
Queue::send(int fd, const void* buf, size_t size, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexScalarSend>(
        *this, fd, buf, size, flags, trace_event
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

rawio::Awaitable<size_t>
Queue::sendmsg(int fd, const msghdr* msg, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, flags = %u\n", fd,
        (unsigned int)msg->msg_iovlen, flags
    );
    Session& s = _get_session(fd);

    std::unique_ptr<Event> event = std::make_unique<EventSimplexMessageWrite>(
        *this, fd, msg, flags, trace_event
    );

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    s.write(std::move(event));
    return rawio::Awaitable<size_t>(this, ret);
}

// Submission (i.e. starting the clock) already happens before this
// returns, exactly like every op above -- the deadline is computed now,
// not whenever _timers is next actually consulted.
rawio::Awaitable<void> Queue::timeout(unsigned int usec) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "usec = %u\n", usec);

    std::chrono::steady_clock::time_point deadline =
        std::chrono::steady_clock::now() + std::chrono::microseconds(usec);

    std::unique_ptr<EventTimer> event =
        std::make_unique<EventTimer>(*this, deadline, trace_event);

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());

    std::list<std::unique_ptr<EventTimer>>::iterator it = _timers.begin();
    while (it != _timers.end() && (*it)->deadline() <= deadline) {
        ++it;
    }
    _timers.insert(it, std::move(event));

    return rawio::Awaitable<void>(this, ret);
}

void Queue::_attach(
    rawio::Event* event, std::coroutine_handle<> h, size_t* value, int* error
) noexcept {
    static_cast<Event*>(event)->attach(h, value, error);
}

// Deferred through EventEval, exactly like open()/close() above, so
// cancel()'s own resolution -- like every other op's -- never happens
// before the next wait()/wait_timeout() call. Always resolves
// successfully for an awaiter: whether the target was actually found is
// not reported here (see cancel()'s doc comment in <rawio/queue.hpp>),
// only that the request itself has been fully processed. The target
// event's own completion, if it was still pending, was already queued
// into _cqes by Session::cancel() by the time that happens.
rawio::Awaitable<void> Queue::cancel(rawio::Event* e) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "event = %p\n", e);

    std::unique_ptr<EventEval> event =
        std::make_unique<EventEval>(*this, trace_event, [this, e]() -> int {
            for (auto& it : _sessions) {
                if (it.second->cancel(e, _cqes)) {
                    return 0;
                }
            }
            for (std::list<std::unique_ptr<EventTimer>>::iterator it =
                     _timers.begin();
                 it != _timers.end(); ++it) {
                if (e == static_cast<rawio::Event*>(it->get())) {
                    // Marked cancelled and re-sorted to the front (its
                    // deadline moved to now(), which -- steady_clock being
                    // monotonic -- always sorts no later than every other
                    // pending timer's still-future deadline) rather than
                    // dispatched inline here: an eval callback's process()
                    // isn't itself exception-safe the way the try/catch
                    // around _reap_timers()'s own dispatch() call is, so
                    // handing this off to the _reap_timers() call right
                    // after this eval-drain loop (see _wait_timeout()) is
                    // what actually resolves it.
                    std::unique_ptr<EventTimer> t = std::move(*it);
                    _timers.erase(it);

                    t->set_error(ECANCELED);
                    t->set_deadline(std::chrono::steady_clock::now());
                    _timers.push_front(std::move(t));
                    return 0;
                }
            }
            if (_current_event != nullptr && e == _current_event) {
                _current_event->set_error(ECANCELED);
            }
            return 0;
        });

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<void>(this, ret);
}

rawio::Awaitable<void> Queue::cancel(int fd) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);

    std::unique_ptr<EventEval> event =
        std::make_unique<EventEval>(*this, trace_event, [this, fd]() -> int {
            auto it = _sessions.find(fd);
            if (it != _sessions.end()) {
                it->second->cancel(_cqes);
                _sessions.erase(it);
            }
            return 0;
        });

    rawio::Event* ret = static_cast<rawio::Event*>(event.get());
    _eval(std::move(event));
    return rawio::Awaitable<void>(this, ret);
}

void Queue::wait() {
    _wait_timeout(-1);
}

void Queue::wait_timeout(unsigned int msec) {
    _wait_timeout(msec);
}

} // namespace poll
} // namespace rawio
