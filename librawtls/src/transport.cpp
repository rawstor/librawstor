#include <rawtls/transport.hpp>

#include <rawio/awaitable.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <algorithm>
#include <cerrno>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <deque>
#include <exception>
#include <utility>
#include <vector>

#include <sys/uio.h>

namespace rawtls {

namespace {

// Hands a lock to coroutines one at a time, in the order they asked. The
// Queue is single-threaded, so this needs no atomics: it only keeps one TLS
// record stream from being interleaved by two sends that are both partly
// written.
class AsyncMutex final {
private:
    bool _locked = false;
    std::deque<std::coroutine_handle<>> _waiters;

public:
    class Acquire final {
    private:
        AsyncMutex& _mutex;

    public:
        explicit Acquire(AsyncMutex& mutex) noexcept : _mutex(mutex) {}

        bool await_ready() noexcept {
            if (_mutex._locked) {
                return false;
            }
            _mutex._locked = true;
            return true;
        }

        void await_suspend(std::coroutine_handle<> h) {
            _mutex._waiters.push_back(h);
        }

        void await_resume() noexcept {}
    };

    class Guard final {
    private:
        AsyncMutex& _mutex;

    public:
        explicit Guard(AsyncMutex& mutex) noexcept : _mutex(mutex) {}
        Guard(const Guard&) = delete;
        Guard& operator=(const Guard&) = delete;
        ~Guard() { _mutex._unlock(); }
    };

    Acquire lock() noexcept { return Acquire(*this); }

private:
    // The lock passes to the first waiter without being released.
    void _unlock() {
        if (_waiters.empty()) {
            _locked = false;
            return;
        }
        std::coroutine_handle<> h = _waiters.front();
        _waiters.pop_front();
        h.resume();
    }
};

class PlainTransport final : public Transport {
private:
    rawio::Queue& _queue;
    int _fd;

public:
    PlainTransport(rawio::Queue& queue, int fd) noexcept :
        _queue(queue),
        _fd(fd) {}

    Op<size_t> send(const void* buf, size_t size, unsigned int flags) override {
        return _queue.send(_fd, buf, size, flags);
    }

    Op<size_t> sendmsg(const msghdr* msg, unsigned int flags) override {
        return _queue.sendmsg(_fd, msg, flags);
    }

    rawio::RecvStream recv_multishot(
        size_t entry_size, unsigned int entries, size_t size, unsigned int flags
    ) override {
        return _queue.recv_multishot(_fd, entry_size, entries, size, flags);
    }

    Op<void> cancel_receive(rawio::Event* event) override {
        return _queue.cancel(event);
    }

    const SpiffeId* peer() const noexcept override { return nullptr; }
};

const size_t cipher_size = 1 << 16;
const size_t record_size = 1 << 14;

// What a TLS Transport and its receive stream share. The stream outlives the
// Transport when the code that reads it is still unwinding, so both hold it
// through a shared_ptr.
struct TlsState {
    rawio::Queue& queue;
    int fd;
    Session session;
    // Orders everything written to the socket: a send takes it from encrypting
    // until the last byte of its records is out.
    AsyncMutex write_mutex;
    std::vector<unsigned char> out;
    // The recv in flight, if any, and whether the stream was told to stop.
    rawio::Event* inflight = nullptr;
    bool cancelled = false;
    // Set once a write failed: part of a record may be on the wire, so nothing
    // can follow it, and the sends waiting their turn fail instead of writing
    // to a socket that is being closed.
    bool broken = false;
    // The handshake's deadline: the timer, whether the handshake is still
    // running, and whether the timer is what ended it.
    rawio::Event* timer = nullptr;
    bool handshaking = true;
    bool timed_out = false;

    TlsState(
        rawio::Queue& q, int f, Context& context, Session::Mode mode,
        const std::string& expected_peer, std::optional<Role> expected_role
    ) :
        queue(q),
        fd(f),
        session(context, mode, expected_peer, expected_role) {}
};

rawstd::Task<void>
write_all(std::shared_ptr<TlsState> s, const unsigned char* p, size_t n) {
    while (n > 0) {
        size_t written = 0;
        try {
            written = co_await s->queue.send(s->fd, p, n, RAWSTD_MSG_NOSIGNAL);
        } catch (...) {
            s->broken = true;
            throw;
        }
        if (written == 0) {
            s->broken = true;
            RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
        }
        p += written;
        n -= written;
    }
}

// Sends what the session has to say. The caller must be the only one writing:
// holding write_mutex, or before the Transport exists.
rawstd::Task<void> flush(std::shared_ptr<TlsState> s) {
    if (s->broken) {
        RAWSTD_THROW_SYSTEM_ERROR(ECONNABORTED);
    }
    for (;;) {
        size_t n = s->session.output_size();
        if (n == 0) {
            co_return;
        }
        s->out.resize(n);
        s->session.take_output(s->out.data(), n);
        co_await write_all(s, s->out.data(), n);
    }
}

rawstd::Task<void> flush_locked(std::shared_ptr<TlsState> s) {
    co_await s->write_mutex.lock();
    AsyncMutex::Guard guard(s->write_mutex);
    co_await flush(s);
}

rawstd::Task<size_t>
tls_send(std::shared_ptr<TlsState> s, const void* buf, size_t size) {
    co_await s->write_mutex.lock();
    AsyncMutex::Guard guard(s->write_mutex);
    s->session.encrypt(buf, size);
    co_await flush(s);
    co_return size;
}

rawstd::Task<size_t>
tls_sendmsg(std::shared_ptr<TlsState> s, const msghdr* msg) {
    co_await s->write_mutex.lock();
    AsyncMutex::Guard guard(s->write_mutex);
    size_t total = 0;
    for (size_t i = 0; i < static_cast<size_t>(msg->msg_iovlen); ++i) {
        const iovec& v = msg->msg_iov[i];
        if (v.iov_len > 0) {
            s->session.encrypt(v.iov_base, v.iov_len);
            total += v.iov_len;
        }
    }
    co_await flush(s);
    co_return total;
}

// Stops the recv in flight and makes the next one fail. A cancel that finds
// nothing in flight (the reader is between recvs) is remembered for the next.
void cancel_receive_now(TlsState& s) noexcept {
    s.cancelled = true;
    if (s.inflight != nullptr) {
        try {
            s.queue.cancel(s.inflight);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel event: %s\n", e.what());
        }
    }
}

rawstd::Task<void> cancel_receive_task(std::shared_ptr<TlsState> s) {
    cancel_receive_now(*s);
    co_return;
}

rawstd::Task<void> tls_handshake(std::shared_ptr<TlsState> s) {
    std::vector<unsigned char> in(record_size);
    std::exception_ptr error;
    try {
        for (;;) {
            bool done = s->session.handshake();
            co_await flush(s);
            if (done) {
                co_return;
            }
            // Registered so the deadline can cancel it.
            rawio::Awaitable<size_t> op =
                s->queue.recv(s->fd, in.data(), in.size(), 0);
            s->inflight = op.event();
            size_t n = 0;
            try {
                n = co_await op;
            } catch (...) {
                s->inflight = nullptr;
                throw;
            }
            s->inflight = nullptr;
            if (n == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
            }
            s->session.feed(in.data(), n);
        }
    } catch (...) {
        error = std::current_exception();
    }
    // A refused handshake leaves an alert for the peer. Failing to send it
    // must not hide why the handshake failed.
    try {
        co_await flush(s);
    } catch (...) {
    }
    std::rethrow_exception(error);
}

/*
 * The decrypted bytes of a connection, handed out like rawio's own receive
 * stream: next(want) completes with exactly `want` bytes once that many have
 * arrived. Nothing is read from the socket unless someone is waiting for it,
 * so a consumer that is busy leaves the data in the socket's buffer.
 */
class TlsRecv final : public rawio::RecvStream::Backend,
                      public std::enable_shared_from_this<TlsRecv> {
private:
    std::shared_ptr<TlsState> _s;
    std::vector<unsigned char> _cipher;
    std::vector<unsigned char> _scratch;
    // The decrypted bytes not yet handed out are _plain[_head..].
    std::vector<unsigned char> _plain;
    size_t _head = 0;
    // Why no more will come, once nothing more will.
    int _terminal = 0;
    bool _reading = false;

    std::coroutine_handle<> _waiter;
    size_t _want = 0;
    rawio::RecvStream::Item* _item = nullptr;
    int* _error = nullptr;

    size_t _available() const noexcept { return _plain.size() - _head; }

    void _fail(int error) noexcept {
        if (_terminal == 0) {
            _terminal = error;
        }
    }

    // Decrypts whatever the session already holds, without reading the
    // socket.
    void _decrypt_buffered() noexcept {
        if (_terminal != 0) {
            return;
        }
        try {
            for (;;) {
                size_t n =
                    _s->session.decrypt(_scratch.data(), _scratch.size());
                if (n == 0) {
                    break;
                }
                _plain.insert(
                    _plain.end(), _scratch.begin(), _scratch.begin() + n
                );
            }
            if (_s->session.closed()) {
                _fail(EPIPE);
            }
        } catch (const std::system_error& e) {
            _fail(e.code().value());
        } catch (...) {
            _fail(EIO);
        }
    }

    void _extract(size_t size, rawio::RecvStream::Item& out) {
        std::shared_ptr<std::vector<unsigned char>> block =
            std::make_shared<std::vector<unsigned char>>(
                _plain.begin() + static_cast<std::ptrdiff_t>(_head),
                _plain.begin() + static_cast<std::ptrdiff_t>(_head + size)
            );
        _head += size;
        if (_head == _plain.size()) {
            _plain.clear();
            _head = 0;
        } else if (_head > (1 << 20)) {
            _plain.erase(
                _plain.begin(),
                _plain.begin() + static_cast<std::ptrdiff_t>(_head)
            );
            _head = 0;
        }
        std::vector<iovec> iov{{block->data(), size}};
        out = rawio::RecvStream::Item(std::move(iov), size, std::move(block));
    }

    // The part of try_produce() that does not touch the session.
    bool _take(size_t want, rawio::RecvStream::Item& out, int& error) noexcept {
        if (_s->cancelled) {
            _fail(ECANCELED);
        }
        size_t available = _available();
        try {
            if (want > 0 && available >= want) {
                _extract(want, out);
                error = 0;
                return true;
            }
            if (_terminal != 0) {
                // What is left goes first, the error on the call after.
                size_t drain = std::min(available, want);
                if (drain > 0) {
                    _extract(drain, out);
                    error = 0;
                    return true;
                }
                error = _terminal;
                return true;
            }
        } catch (const std::bad_alloc&) {
            error = ENOMEM;
            return true;
        }
        return false;
    }

    // Completes the waiting next() if what arrived satisfies it. True when
    // the reader has nothing more to do.
    bool _deliver() {
        if (!_waiter) {
            _reading = false;
            return true;
        }
        rawio::RecvStream::Item out;
        int error = 0;
        if (!_take(_want, out, error)) {
            return false;
        }
        std::coroutine_handle<> h = std::exchange(_waiter, nullptr);
        if (error == 0) {
            *_item = std::move(out);
        }
        *_error = error;
        _item = nullptr;
        _error = nullptr;
        _reading = false;
        h.resume();
        return true;
    }

    static rawstd::DetachedTask _run(std::shared_ptr<TlsRecv> self) {
        TlsState& s = *self->_s;
        for (;;) {
            if (s.cancelled) {
                self->_fail(ECANCELED);
            } else {
                try {
                    rawio::Awaitable<size_t> op = s.queue.recv(
                        s.fd, self->_cipher.data(), self->_cipher.size(), 0
                    );
                    s.inflight = op.event();
                    size_t n = 0;
                    try {
                        n = co_await op;
                    } catch (...) {
                        s.inflight = nullptr;
                        throw;
                    }
                    s.inflight = nullptr;
                    if (n == 0) {
                        self->_fail(EPIPE);
                    } else {
                        s.session.feed(self->_cipher.data(), n);
                    }
                } catch (const std::system_error& e) {
                    self->_fail(e.code().value());
                }
                self->_decrypt_buffered();
                // A key update the peer asked for, or an alert, waits in the
                // output.
                if (self->_terminal == 0 && s.session.output_size() > 0) {
                    try {
                        co_await flush_locked(self->_s);
                    } catch (const std::system_error& e) {
                        self->_fail(e.code().value());
                    }
                }
            }
            if (self->_deliver()) {
                co_return;
            }
        }
    }

public:
    explicit TlsRecv(std::shared_ptr<TlsState> state) :
        _s(std::move(state)),
        _cipher(cipher_size),
        _scratch(record_size) {}

    bool try_produce(
        size_t want, rawio::RecvStream::Item& out, int& error
    ) noexcept override {
        _decrypt_buffered();
        return _take(want, out, error);
    }

    void set_waiter(
        std::coroutine_handle<> h, size_t want, rawio::RecvStream::Item* out,
        int* error
    ) noexcept override {
        _waiter = h;
        _want = want;
        _item = out;
        _error = error;
        if (!_reading) {
            _reading = true;
            _run(shared_from_this());
        }
    }

    void close() noexcept override { cancel_receive_now(*_s); }

    rawio::Event* event() const noexcept override {
        return const_cast<TlsRecv*>(this);
    }
};

class TlsTransport final : public Transport {
private:
    std::shared_ptr<TlsState> _s;

public:
    explicit TlsTransport(std::shared_ptr<TlsState> state) :
        _s(std::move(state)) {}

    Op<size_t> send(const void* buf, size_t size, unsigned int) override {
        return tls_send(_s, buf, size);
    }

    Op<size_t> sendmsg(const msghdr* msg, unsigned int) override {
        return tls_sendmsg(_s, msg);
    }

    rawio::RecvStream
    recv_multishot(size_t, unsigned int, size_t, unsigned int) override {
        _s->cancelled = false;
        return rawio::RecvStream(std::make_shared<TlsRecv>(_s));
    }

    Op<void> cancel_receive(rawio::Event*) override {
        return cancel_receive_task(_s);
    }

    const SpiffeId* peer() const noexcept override {
        return &_s->session.peer();
    }
};

} // namespace

std::unique_ptr<Transport> Transport::plain(rawio::Queue& queue, int fd) {
    return std::make_unique<PlainTransport>(queue, fd);
}

namespace {

// Ends the handshake if the peer has not finished it in time, by cancelling the
// recv it is waiting in.
rawstd::DetachedTask
handshake_deadline(std::shared_ptr<TlsState> s, unsigned int timeout_ms) {
    rawio::Awaitable<void> timer = s->queue.timeout(timeout_ms * 1000u);
    s->timer = timer.event();
    try {
        co_await timer;
    } catch (const std::system_error&) {
        // Cancelled: the handshake ended first.
        s->timer = nullptr;
        co_return;
    }
    s->timer = nullptr;
    if (s->handshaking) {
        s->timed_out = true;
        cancel_receive_now(*s);
    }
}

} // namespace

rawstd::Task<std::unique_ptr<Transport>> Transport::tls(
    rawio::Queue& queue, int fd, Context& context, Session::Mode mode,
    const std::string& expected_peer, std::optional<Role> expected_role,
    unsigned int handshake_timeout_ms
) {
    std::shared_ptr<TlsState> state = std::make_shared<TlsState>(
        queue, fd, context, mode, expected_peer, expected_role
    );
    handshake_deadline(state, handshake_timeout_ms);
    rawstd::DetachedTask::rethrow_if_pending();

    std::exception_ptr error;
    try {
        co_await tls_handshake(state);
    } catch (...) {
        error = std::current_exception();
    }
    state->handshaking = false;
    if (state->timer != nullptr) {
        try {
            queue.cancel(state->timer);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel event: %s\n", e.what());
        }
    }
    if (error) {
        if (state->timed_out) {
            RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
        }
        std::rethrow_exception(error);
    }
    // The deadline's cancel is not the stream's: a stream starts afresh.
    state->cancelled = false;
    co_return std::make_unique<TlsTransport>(std::move(state));
}

} // namespace rawtls
