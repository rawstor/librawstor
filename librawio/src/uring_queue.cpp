#include "uring_queue.hpp"

#include "uring_buffer.hpp"

#include <rawio/awaitable.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>

#include <cstring>
#include <ctime>

#include <system_error>

namespace {

std::string engine_name = "uring";

} // namespace

namespace rawio {
namespace uring {

namespace {

// Runs setup_fd() on a successful accept() raw result, folding any
// setup_fd() failure into a negative errno rather than leaking the fd.
// Shared by accept()'s AcceptCompletion and accept_multishot()'s
// AcceptMultishotCompletion below.
int setup_accepted_fd(int raw_result) {
    if (raw_result < 0) {
        return raw_result;
    }
    try {
        rawio::uring::Queue::setup_fd(raw_result);
        return raw_result;
    } catch (const std::system_error& e) {
        rawstd_error("Failed to setup fd %d: %s\n", raw_result, e.what());
        ::close(raw_result);
        return -e.code().value();
    } catch (const std::exception& e) {
        rawstd_error("Failed to setup fd %d: %s\n", raw_result, e.what());
        ::close(raw_result);
        return -EIO;
    } catch (...) {
        rawstd_error("Failed to setup fd %d\n", raw_result);
        ::close(raw_result);
        return -EIO;
    }
}

/*
 * The single heap-allocated completion token stored via
 * io_uring_sqe_set_data()/io_uring_cqe_get_data() for every op this
 * backend submits. complete() is _dispatch()'s single, uniform entry
 * point for turning one raw CQE into whatever that op's completion means
 * -- resuming a coroutine (the base implementation, used by every
 * single-shot op) or feeding a multishot backend/buffer (subclasses
 * below), so _dispatch() itself never needs to know which kind of op a
 * given completion belongs to.
 */
class Completion {
protected:
    std::coroutine_handle<> _handle;
    size_t* _value_ptr;
    int* _error_ptr;

public:
    rawstd::TraceEvent trace_event;

    explicit Completion(rawstd::TraceEvent trace_event) :
        _handle(),
        _value_ptr(nullptr),
        _error_ptr(nullptr),
        trace_event(std::move(trace_event)) {}

    virtual ~Completion() = default;

    // Called once from Queue::_attach() (itself called from
    // Awaitable<T>::await_suspend()), before the next
    // wait()/wait_timeout() call reaps this operation's CQE.
    void attach(std::coroutine_handle<> h, size_t* value, int* error) noexcept {
        _handle = h;
        _value_ptr = value;
        _error_ptr = error;
    }

    // Turns a raw io_uring completion result (negative -errno, or a
    // non-negative success value) into _value_ptr/_error_ptr and resumes
    // whoever is co_await-ing it -- the same negative-errno convention
    // every single-shot op already used when it passed its raw `result`
    // straight to a `std::function<void(int)>`/split it into a
    // `std::function<void(size_t, int)>` callback. `flags` is the CQE's
    // flags (unused by single-shot ops, which never carry
    // IORING_CQE_F_MORE); multishot subclasses use it.
    //
    // Resuming a rawstd::DetachedTask (the rawio.cpp C shim's adapters
    // are the only thing that ever attaches one via attach()) that then
    // throws doesn't throw back out of resume() itself -- see
    // DetachedTask's own doc comment -- but _dispatch() still needs to
    // check DetachedTask::rethrow_if_pending() right after this call.
    virtual void complete(int raw_result, unsigned int /*flags*/) {
        if (raw_result >= 0) {
            if (_value_ptr) {
                *_value_ptr = static_cast<size_t>(raw_result);
            }
            if (_error_ptr) {
                *_error_ptr = 0;
            }
        } else {
            if (_value_ptr) {
                *_value_ptr = 0;
            }
            if (_error_ptr) {
                *_error_ptr = -raw_result;
            }
        }

        if (_handle) {
            _handle.resume();
        }
    }
};

// accept()'s Completion: a successful raw result (the new fd) must run
// through setup_fd() before it's usable.
class AcceptCompletion final : public Completion {
public:
    explicit AcceptCompletion(rawstd::TraceEvent trace_event) :
        Completion(std::move(trace_event)) {}

    void complete(int raw_result, unsigned int flags) override {
        Completion::complete(setup_accepted_fd(raw_result), flags);
    }
};

// cancel()'s own completion token: fire-and-forget, nothing to resume and
// no result the caller can observe -- the cancellation's actual effect (if
// any) is the target operation's own eventual completion (ECANCELED, or
// its natural result if the cancellation lost the race). -ENOENT (target
// already gone) and -EALREADY (cancellation already in flight) are both
// entirely ordinary outcomes here, not failures worth logging; anything
// else is unexpected enough to warn about.
class CancelCompletion final : public Completion {
public:
    explicit CancelCompletion(rawstd::TraceEvent trace_event) :
        Completion(std::move(trace_event)) {}

    void complete(int raw_result, unsigned int flags) override {
        if (raw_result < 0 && raw_result != -ENOENT &&
            raw_result != -EALREADY) {
            rawstd_warning(
                "Unexpected cancel completion result: %d\n", raw_result
            );
        }
        // Resolve successfully for an awaiter regardless of the raw
        // result -- ENOENT/EALREADY are ordinary outcomes here, not
        // failures, and an awaiter only ever learns that the
        // cancellation request itself has been fully processed, never
        // whether the target was actually found (see cancel()'s doc
        // comment in <rawio/queue.hpp>).
        Completion::complete(0, flags);
    }
};

// timeout()'s own completion token: a plain -ETIME (the CQE result a
// timeout naturally completes with once it fires, absent
// IORING_TIMEOUT_ETIME_SUCCESS -- which is set at submission, but gets
// translated here too rather than relied on alone; observed to not
// actually suppress -ETIME on at least one real kernel/liburing pair this
// was tested against, despite being documented to since 5.15) is this
// op's ordinary successful completion, not a failure -- a caller
// co_await-ing timeout() shouldn't have to special-case ETIME the way
// every other op's caller has to treat it as a real error. ECANCELED
// (from cancel(Event*)) is untouched and still surfaces as a thrown
// exception, exactly like every other op.
class TimeoutCompletion final : public Completion {
public:
    explicit TimeoutCompletion(rawstd::TraceEvent trace_event) :
        Completion(std::move(trace_event)) {}

    void complete(int raw_result, unsigned int flags) override {
        Completion::complete(raw_result == -ETIME ? 0 : raw_result, flags);
    }
};

/*
 * Shared single-slot "pull" backend for poll_multishot()/
 * accept_multishot(): both just deliver a plain int (revents mask, or an
 * accepted fd) per completion, with the same at-most-one-pending-slot +
 * ENOBUFS-on-overflow policy and the same _dispatch_generation same-batch
 * dedup poll_multishot always needed. `OnCompletion` distinguishes them
 * only in how a raw completion result is turned into the delivered value
 * (accept_multishot additionally runs setup_fd() on success).
 *
 * `dedup` controls the _dispatch_generation same-batch check: on for
 * poll_multishot (a same-batch re-notification genuinely can be a stale
 * duplicate -- see uring::Queue::_dispatch_generation), off for
 * accept_multishot (every completion carries a *new* accepted fd, never a
 * duplicate of a prior one, so collapsing same-batch completions would
 * silently drop real connections -- matches today's accept_multishot,
 * which never had generation-dedup logic).
 */
template <typename BackendBase, bool dedup>
class SingleSlotStreamBackend final : public BackendBase {
private:
    Queue& _q;
    unsigned int _last_generation;

    std::coroutine_handle<> _waiter;
    int* _waiter_out;
    int* _waiter_error;

    bool _has_pending;
    int _pending_value;
    int _pending_error;
    bool _pending_overflow;

    bool _closed;
    bool _terminated;
    int _terminal_error;

    Event* _event;

public:
    SingleSlotStreamBackend(Queue& q, unsigned int last_generation) :
        _q(q),
        _last_generation(last_generation),
        _waiter(),
        _waiter_out(nullptr),
        _waiter_error(nullptr),
        _has_pending(false),
        _pending_value(0),
        _pending_error(0),
        _pending_overflow(false),
        _closed(false),
        _terminated(false),
        _terminal_error(0),
        _event(nullptr) {}

    inline void set_event(Event* event) noexcept { _event = event; }

    bool try_produce(int& out, int& error) noexcept override {
        if (_has_pending) {
            out = _pending_value;
            error = _pending_error;
            bool was_error = _pending_error != 0;
            _has_pending = false;
            if (_pending_overflow && !was_error) {
                // Deliver this item now; the overflow that arrived while
                // it sat unconsumed surfaces on the *next* call instead
                // of silently discarding either one.
                _terminated = true;
                _terminal_error = ENOBUFS;
            }
            return true;
        }
        if (_pending_overflow) {
            _pending_overflow = false;
            error = ENOBUFS;
            _terminated = true;
            _terminal_error = ENOBUFS;
            return true;
        }
        if (_terminated) {
            error = _terminal_error;
            return true;
        }
        return false;
    }

    void set_waiter(
        std::coroutine_handle<> h, int* out, int* error
    ) noexcept override {
        _waiter = h;
        _waiter_out = out;
        _waiter_error = error;
    }

    void close() noexcept override {
        _closed = true;
        if (_event != nullptr && !_terminated) {
            try {
                _q.cancel(_event);
            } catch (...) {
            }
        }
    }

    rawio::Event* event() const noexcept override { return _event; }

    // Called from the uring completion path (see poll_multishot()/
    // accept_multishot() below) with the already-setup_fd()-resolved,
    // negative-errno-or-non-negative-value convention. Resuming a
    // rawstd::DetachedTask here that then throws is handled the same way
    // as Completion::complete() above -- see its comment and
    // DetachedTask's own doc comment.
    void on_completion(int value, int error) {
        if (_closed) {
            return;
        }
        if constexpr (dedup) {
            if (_last_generation == _q.dispatch_generation()) {
                // Same-batch duplicate wakeup, see uring::Queue's
                // _dispatch_generation doc comment.
                return;
            }
            _last_generation = _q.dispatch_generation();
        }

        if (_waiter) {
            auto h = std::exchange(_waiter, nullptr);
            *_waiter_out = value;
            *_waiter_error = error;
            _waiter_out = nullptr;
            _waiter_error = nullptr;
            if (error) {
                _terminated = true;
                _terminal_error = error;
            }
            h.resume();
            return;
        }

        if (_has_pending) {
            // Consumer hasn't picked up the previous delivery yet: remember
            // the overflow, to be reported once it does (see
            // try_produce()).
            _pending_overflow = true;
            return;
        }

        if (error) {
            _terminated = true;
            _terminal_error = error;
        }
        _has_pending = true;
        _pending_value = value;
        _pending_error = error;
    }
};

using PollMultishotBackend =
    SingleSlotStreamBackend<rawio::PollStream::Backend, /*dedup=*/true>;
using AcceptMultishotBackend =
    SingleSlotStreamBackend<rawio::AcceptStream::Backend, /*dedup=*/false>;

// poll_multishot()'s Completion: each CQE just carries a plain revents
// mask (or an error) into the shared single-slot backend.
class PollMultishotCompletion final : public Completion {
private:
    std::shared_ptr<PollMultishotBackend> _backend;

public:
    PollMultishotCompletion(
        rawstd::TraceEvent trace_event,
        std::shared_ptr<PollMultishotBackend> backend
    ) :
        Completion(std::move(trace_event)),
        _backend(std::move(backend)) {}

    void complete(int raw_result, unsigned int /*flags*/) override {
        if (raw_result >= 0) {
            _backend->on_completion(raw_result, 0);
        } else {
            _backend->on_completion(0, -raw_result);
        }
    }
};

// accept_multishot()'s Completion: same shape as PollMultishotCompletion,
// except a successful raw result (the new fd) must run through
// setup_accepted_fd() first, exactly like accept()'s AcceptCompletion.
class AcceptMultishotCompletion final : public Completion {
private:
    std::shared_ptr<AcceptMultishotBackend> _backend;

public:
    AcceptMultishotCompletion(
        rawstd::TraceEvent trace_event,
        std::shared_ptr<AcceptMultishotBackend> backend
    ) :
        Completion(std::move(trace_event)),
        _backend(std::move(backend)) {}

    void complete(int raw_result, unsigned int /*flags*/) override {
        raw_result = setup_accepted_fd(raw_result);
        if (raw_result >= 0) {
            _backend->on_completion(raw_result, 0);
        } else {
            _backend->on_completion(0, -raw_result);
        }
    }
};

// recv_multishot()'s Completion: unlike the other two multishot ops,
// BufferRing::on_arrival() also needs the CQE's flags (buffer-ring
// bookkeeping), so `flags` is forwarded rather than ignored.
class RecvMultishotCompletion final : public Completion {
private:
    std::shared_ptr<BufferRing> _buffer;

public:
    RecvMultishotCompletion(
        rawstd::TraceEvent trace_event, std::shared_ptr<BufferRing> buffer
    ) :
        Completion(std::move(trace_event)),
        _buffer(std::move(buffer)) {}

    void complete(int raw_result, unsigned int flags) override {
        _buffer->on_arrival(raw_result, flags);
    }
};

} // namespace

Queue::Queue(unsigned int depth) :
    rawio::Queue(depth),
    _dispatch_generation(0) {
    int res = io_uring_queue_init(
        depth, &_ring, IORING_SETUP_SUBMIT_ALL | IORING_SETUP_COOP_TASKRUN
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    };
}

Queue::~Queue() {
    int res = io_uring_submit(&_ring);
    if (res < 0) {
        rawstd_error("Failed to submit sqes: %s\n", strerror(-res));
    } else {
        io_uring_sync_cancel_reg req = {};
        req.flags = IORING_ASYNC_CANCEL_ANY;
        res = io_uring_register_sync_cancel(&_ring, &req);
        if (res < 0) {
            rawstd_error("Failed to cancel sqes: %s\n", strerror(-res));
        } else {
            while (true) {
                try {
                    wait_timeout(0);
                } catch (const std::system_error& e) {
                    if (e.code().value() != ETIME) {
                        rawstd_error("Failed to wait: %s\n", e.what());
                    }
                    break;
                } catch (const std::exception& e) {
                    rawstd_error("Failed to wait: %s\n", e.what());
                    break;
                }
            }
        }
    }

    io_uring_queue_exit(&_ring);
}

void Queue::_dispatch() {
    unsigned int nr = 0;

    ++_dispatch_generation;

    try {
        unsigned int head;
        io_uring_cqe* cqe;
        io_uring_for_each_cqe(&_ring, head, cqe) {
            rawstd_trace("cqe->res = %d\n", cqe->res);

            ++nr;

            std::unique_ptr<Completion> c(
                static_cast<Completion*>(io_uring_cqe_get_data(cqe))
            );

            RAWSTD_TRACE_EVENT_MESSAGE(
                c->trace_event, "result = %d, flags = %u\n", cqe->res,
                cqe->flags
            );

            try {
                c->complete(cqe->res, cqe->flags);
                // complete() may have resumed a rawstd::DetachedTask that
                // threw -- see DetachedTask's own doc comment for why
                // that can't be delivered by rethrowing directly out of
                // complete()/resume() itself, and rethrow_if_pending()'s
                // for why this is one of only two places that need to
                // check.
                rawstd::DetachedTask::rethrow_if_pending();
            } catch (...) {
                rawstd_trace("complete error\n");
                if (cqe->flags & IORING_CQE_F_MORE) {
                    c.release();
                }
                throw;
            }

            if (cqe->flags & IORING_CQE_F_MORE) {
                c.release();
            }
        }
    } catch (...) {
        if (nr) {
            io_uring_cq_advance(&_ring, nr);
        }
        throw;
    }

    if (nr) {
        // TODO: use __io_uring_buf_ring_cq_advance here
        io_uring_cq_advance(&_ring, nr);
    }
}

const std::string& Queue::engine_name() {
    return ::engine_name;
}

void Queue::setup_fd(int fd) {
    int res;
    static unsigned int bufsize = 16 * 1024 * 1024;

    // No-op on Linux (send()/sendmsg() suppress SIGPIPE per-call via
    // MSG_NOSIGNAL instead); kept for parity with the poll backend, which
    // also runs on macOS, where this is the only way to suppress it.
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
        RAWSTD_TRACE_EVENT('|', "flags = %d, mode = %u\n", flags, mode);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_openat(sqe, AT_FDCWD, path, flags, mode);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::Awaitable<int> Queue::close(int fd) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "%s\n", "");
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_close(sqe, fd);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::Awaitable<int> Queue::poll(int fd, unsigned int mask) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_poll_add(sqe, fd, mask);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::PollStream Queue::poll_multishot(int fd, unsigned int mask) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, mask = %u\n", fd, mask);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_poll_multishot(sqe, fd, mask);

    auto backend =
        std::make_shared<PollMultishotBackend>(*this, _dispatch_generation);
    auto c = std::make_unique<PollMultishotCompletion>(
        std::move(trace_event), backend
    );
    io_uring_sqe_set_data(sqe, c.get());
    backend->set_event(static_cast<rawio::Event*>(c.release()));

    return rawio::PollStream(std::move(backend));
}

rawio::Awaitable<int>
Queue::accept(int fd, sockaddr* addr, socklen_t* addrlen) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<AcceptCompletion>(std::move(trace_event));
    io_uring_prep_accept(sqe, fd, addr, addrlen, 0);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::AcceptStream Queue::accept_multishot(int fd) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_multishot_accept(sqe, fd, nullptr, nullptr, 0);

    auto backend =
        std::make_shared<AcceptMultishotBackend>(*this, _dispatch_generation);
    auto c = std::make_unique<AcceptMultishotCompletion>(
        std::move(trace_event), backend
    );
    io_uring_sqe_set_data(sqe, c.get());
    backend->set_event(static_cast<rawio::Event*>(c.release()));

    return rawio::AcceptStream(std::move(backend));
}

rawio::Awaitable<int>
Queue::connect(int fd, const sockaddr* addr, socklen_t addrlen) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_connect(sqe, fd, addr, addrlen);
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::Awaitable<size_t> Queue::read(int fd, void* buf, size_t size) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, buf, size, 0);
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t> Queue::readv(int fd, iovec* iov, unsigned int niov) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, niov = %zu\n", fd, niov);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, iov, niov, 0);
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t>
Queue::pread(int fd, void* buf, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd\n", fd, size, (intmax_t)offset
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_read(sqe, fd, buf, size, offset);
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t>
Queue::preadv(int fd, iovec* iov, unsigned int niov, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd\n", fd, niov, (intmax_t)offset
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_readv(sqe, fd, iov, niov, offset);
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t>
Queue::recv(int fd, void* buf, size_t size, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv(sqe, fd, buf, size, flags);
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
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
    std::shared_ptr<BufferRing> buffer =
        std::make_shared<BufferRing>(*this, _ring, entry_size, entries);

    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_recv_multishot(sqe, fd, nullptr, 0, flags);
    sqe->flags |= IOSQE_BUFFER_SELECT;
    sqe->buf_group = buffer->id();
    auto c = std::make_unique<RecvMultishotCompletion>(
        std::move(trace_event), buffer
    );
    io_uring_sqe_set_data(sqe, c.get());
    buffer->set_event(static_cast<rawio::Event*>(c.release()));

    return rawio::RecvStream(std::move(buffer));
}

rawio::Awaitable<size_t>
Queue::recvmsg(int fd, msghdr* msg, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %zu, flags = %u\n", fd, msg->msg_iovlen, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_recvmsg(sqe, fd, msg, flags);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t> Queue::write(int fd, const void* buf, size_t size) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, size = %zu\n", fd, size);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_write(sqe, fd, buf, size, 0);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t>
Queue::writev(int fd, const iovec* iov, unsigned int niov) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, niov = %u\n", fd, niov);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_writev(sqe, fd, iov, niov, 0);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t>
Queue::pwrite(int fd, const void* buf, size_t size, off_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, offset = %jd, sync = %d\n", fd, size,
        (intmax_t)offset, sync
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_write(sqe, fd, buf, size, offset);
    if (sync) {
        sqe->rw_flags |= RWF_DSYNC;
    }
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t> Queue::pwritev(
    int fd, const iovec* iov, unsigned int niov, off_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %u, offset = %jd, sync = %d\n", fd, niov,
        (intmax_t)offset, sync
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_writev(sqe, fd, iov, niov, offset);
    if (sync) {
        sqe->rw_flags |= RWF_DSYNC;
    }
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<int> Queue::fsync(int fd, bool datasync) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "fd = %d, datasync = %d\n", fd, datasync);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_fsync(sqe, fd, datasync ? IORING_FSYNC_DATASYNC : 0);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::Awaitable<int>
Queue::fallocate(int fd, int mode, off_t offset, off_t len) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, mode = %d, offset = %jd, len = %jd\n", fd, mode,
        (intmax_t)offset, (intmax_t)len
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_fallocate(sqe, fd, mode, offset, len);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<int>(this, static_cast<rawio::Event*>(c.release()));
}

rawio::Awaitable<size_t>
Queue::send(int fd, const void* buf, size_t size, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, size = %zu, flags = %u\n", fd, size, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_send(sqe, fd, buf, size, flags);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<size_t>
Queue::sendmsg(int fd, const msghdr* msg, unsigned int flags) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        '|', "fd = %d, niov = %zu, flags = %u\n", fd, msg->msg_iovlen, flags
    );
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    auto c = std::make_unique<Completion>(std::move(trace_event));
    io_uring_prep_sendmsg(sqe, fd, msg, flags);
    io_uring_sqe_set_data(sqe, c.get());

    return rawio::Awaitable<size_t>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

// Unlike every op above, this one's timer has to start counting the moment
// timeout() is called, not whenever the caller next happens to enter
// wait()/wait_timeout() -- so, like cancel() below (see its own comment),
// this submits the SQE immediately instead of leaving it for the next
// io_uring_submit_and_wait() to flush. `count = 0` -- the batching count
// that lets a plain IORING_OP_TIMEOUT double as "wait for N *other*
// completions or this timeout, whichever first" (what wait_timeout()'s
// io_uring_submit_and_wait_timeout() call uses under the hood) doesn't
// apply here: this is a standalone timer, indifferent to whatever else
// completes on the ring meanwhile. IORING_TIMEOUT_ETIME_SUCCESS documents
// that natural expiry completes with res=0 instead of -ETIME, but
// TimeoutCompletion (above) does that translation itself too rather than
// relying on the flag alone -- so awaiting this resolves without throwing
// either way; ECANCELED, from cancel(), remains the only way it ever
// throws. No IORING_TIMEOUT_ABS/BOOTTIME/REALTIME flag -- `ts` is a plain
// relative duration against CLOCK_MONOTONIC, exactly what a wait timeout
// needs.
rawio::Awaitable<void> Queue::timeout(unsigned int usec) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "usec = %u\n", usec);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    __kernel_timespec ts = {
        .tv_sec = usec / 1'000'000u,
        .tv_nsec = 1000ll * static_cast<long long>(usec % 1'000'000u),
    };
    auto c = std::make_unique<TimeoutCompletion>(std::move(trace_event));
    io_uring_prep_timeout(sqe, &ts, /*count=*/0, IORING_TIMEOUT_ETIME_SUCCESS);
    io_uring_sqe_set_data(sqe, c.get());

    int res = io_uring_submit(&_ring);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    return rawio::Awaitable<void>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

// Both overloads below submit an IORING_OP_ASYNC_CANCEL request and return
// as soon as it's submitted -- unlike io_uring_register_sync_cancel() (the
// previous implementation), submitting an SQE never reaps completions off
// this ring, so this is safe to call from anywhere, including from a
// Completion::complete() callback invoked by _dispatch() itself while it's
// still mid-batch (e.g. a coroutine's destructor unwinding synchronously
// as a side effect of a completion it didn't ask for). Awaiting the
// returned Awaitable<void> is optional -- see cancel()'s doc comment in
// <rawio/queue.hpp>; CancelCompletion above always resolves it
// successfully, whatever the cancel op's own raw result. The target
// operation's own eventual completion (ECANCELED, or its natural result if
// the cancellation lost the race) is the only place the caller can observe
// the actual effect.
rawio::Awaitable<void> Queue::cancel(rawio::Event* event) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('|', "event = %p\n", event);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_cancel(sqe, event, 0);
    auto c = std::make_unique<CancelCompletion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    int res = io_uring_submit(&_ring);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    return rawio::Awaitable<void>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

rawio::Awaitable<void> Queue::cancel(int fd) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('|', "fd = %d\n", fd);
    io_uring_sqe* sqe = io_uring_get_sqe(&_ring);
    if (sqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOBUFS);
    }
    io_uring_prep_cancel_fd(sqe, fd, IORING_ASYNC_CANCEL_ALL);
    auto c = std::make_unique<CancelCompletion>(std::move(trace_event));
    io_uring_sqe_set_data(sqe, c.get());

    int res = io_uring_submit(&_ring);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    return rawio::Awaitable<void>(
        this, static_cast<rawio::Event*>(c.release())
    );
}

void Queue::wait() {
    rawstd_trace("io_uring_submit_and_wait()\n");
    // Ideally used with a ring setup with
    // IORING_SETUP_SINGLE_ISSUER|IORING_SETUP_DEFER_TASKRUN as that will
    // greatly reduce the number of context switches that an application
    // will see waiting on multiple requests.
    int res = io_uring_submit_and_wait(&_ring, 1);
    rawstd_trace("io_uring_submit_and_wait(): res = %d\n", res);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    _dispatch();
}

void Queue::wait_timeout(unsigned int timeout) {
    io_uring_cqe* cqe;
    __kernel_timespec ts = {
        .tv_sec = timeout / 1000, .tv_nsec = 1000000u * (timeout % 1000)
    };
    rawstd_trace("io_uring_submit_and_wait_timeout()\n");
    int res = io_uring_submit_and_wait_timeout(&_ring, &cqe, 1, &ts, nullptr);
    rawstd_trace("io_uring_submit_and_wait_timeout(): res = %d\n", res);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    if (cqe == nullptr) {
        RAWSTD_THROW_SYSTEM_ERROR(ETIME);
    }

    _dispatch();
}

void Queue::_attach(
    rawio::Event* event, std::coroutine_handle<> h, size_t* value, int* error
) noexcept {
    static_cast<Completion*>(event)->attach(h, value, error);
}

} // namespace uring
} // namespace rawio
