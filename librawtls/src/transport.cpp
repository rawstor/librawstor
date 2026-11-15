#include <rawtls/transport.hpp>

#include <rawtls/context.hpp>
#include <rawtls/spiffe.hpp>

#include <rawio/awaitable.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <exception>
#include <memory>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>

#include <sys/uio.h>

namespace {

// Gives the unit back to the semaphore when the coroutine that took it ends.
class Release final {
private:
    rawstd::Semaphore& _semaphore;

public:
    explicit Release(rawstd::Semaphore& semaphore) noexcept :
        _semaphore(semaphore) {}
    Release(const Release&) = delete;
    Release& operator=(const Release&) = delete;
    ~Release() { _semaphore.release(); }
};

int chunk(size_t size) noexcept {
    return static_cast<int>(std::min<size_t>(size, INT_MAX));
}

void log_errors(const char* what) {
    unsigned long code;
    char text[256];
    while ((code = ERR_get_error()) != 0) {
        ERR_error_string_n(code, text, sizeof(text));
        rawstd_error("%s: %s\n", what, text);
    }
}

[[noreturn]] void refuse(const char* reason) {
    rawstd_warning("Peer refused: %s\n", reason);
    RAWSTD_THROW_SYSTEM_ERROR(EACCES);
}

class PlainTransport final : public rawtls::Transport {
private:
    rawio::Queue& _queue;
    int _fd;
    rawio::RecvStream::Canceller _recv;

public:
    PlainTransport(rawio::Queue& queue, int fd) noexcept :
        _queue(queue),
        _fd(fd) {}

    rawstd::Task<size_t>
    send(const void* buf, size_t size, unsigned int flags) override {
        co_return co_await _queue.send(_fd, buf, size, flags);
    }

    rawstd::Task<size_t>
    sendmsg(const msghdr* msg, unsigned int flags) override {
        co_return co_await _queue.sendmsg(_fd, msg, flags);
    }

    rawio::RecvStream recv_multishot(
        size_t entry_size, unsigned int entries, size_t size, unsigned int flags
    ) override {
        rawio::RecvStream stream =
            _queue.recv_multishot(_fd, entry_size, entries, size, flags);
        _recv = stream.canceller();
        return stream;
    }

    void cancel_recv_multishot() noexcept override { _recv.cancel(); }

    const rawtls::SpiffeId* peer() const noexcept override { return nullptr; }
};

const size_t cipher_size = 1 << 16;
const size_t record_size = 1 << 14;

class TlsRecv;

/*
 * A Transport over a TLS connection. Operations started on it (sends, the
 * handshake) must have finished before it is destroyed. Its receive stream
 * need not: the stream outlives it when the code that reads it is still
 * unwinding, and fails with ECANCELED from then on.
 */
class TlsTransport final : public rawtls::Transport {
private:
    friend class TlsRecv;

    rawio::Queue& _queue;
    int _fd;
    std::shared_ptr<ssl_ctx_st> _ctx;
    ssl_st* _ssl = nullptr;
    bio_st* _rbio = nullptr;
    bio_st* _wbio = nullptr;
    rawtls::Mode _mode;
    std::string _trust_domain;
    std::string _expected_peer;
    rawtls::Role _expected_role = rawtls::Role::ost;
    std::optional<rawtls::SpiffeId> _peer;
    bool _handshake_done = false;
    bool _verify_failed = false;
    // True once the peer has said it will send no more.
    bool _closed = false;
    // Orders everything written to the socket: a send takes it from encrypting
    // until the last byte of its records is out.
    rawstd::Semaphore _write_mutex{1};
    std::vector<unsigned char> _out;
    // The recv in flight, if any, and whether the stream was told to stop.
    rawio::Event* _inflight = nullptr;
    bool _cancelled = false;
    std::weak_ptr<TlsRecv> _recv;
    // Set once a write failed: part of a record may be on the wire, so nothing
    // can follow it, and the sends waiting their turn fail instead of writing
    // to a socket that is being closed.
    bool _broken = false;
    // The handshake's deadline: the timer, whether the handshake is still
    // running, whether the timer is what ended it, and whether the deadline's
    // coroutine is done with this object (and who waits for that).
    rawio::Event* _timer = nullptr;
    bool _handshaking = true;
    bool _timed_out = false;
    bool _deadline_over = false;
    std::coroutine_handle<> _deadline_waiter;

    // Ends the deadline's use of this object. Must be the last thing it does:
    // the waiter may destroy the object.
    void _deadline_finish() noexcept {
        _deadline_over = true;
        if (_deadline_waiter) {
            std::exchange(_deadline_waiter, nullptr).resume();
        }
    }

    struct DeadlineOver {
        TlsTransport& t;
        bool await_ready() const noexcept { return t._deadline_over; }
        void await_suspend(std::coroutine_handle<> h) noexcept {
            t._deadline_waiter = h;
        }
        void await_resume() const noexcept {}
    };

    static int _verify(int ok, x509_store_ctx_st* store_ctx) {
        SSL* ssl = static_cast<SSL*>(X509_STORE_CTX_get_ex_data(
            store_ctx, SSL_get_ex_data_X509_STORE_CTX_idx()
        ));
        TlsTransport* self = static_cast<TlsTransport*>(SSL_get_app_data(ssl));
        if (!ok) {
            self->_verify_failed = true;
            return 0;
        }
        // The chain is walked from the root down to the peer's own
        // certificate, which is the one that carries the identity.
        if (X509_STORE_CTX_get_error_depth(store_ctx) != 0) {
            return 1;
        }
        try {
            self->_peer =
                self->_check_peer(X509_STORE_CTX_get_current_cert(store_ctx));
        } catch (const std::system_error&) {
            self->_verify_failed = true;
            X509_STORE_CTX_set_error(
                store_ctx, X509_V_ERR_APPLICATION_VERIFICATION
            );
            return 0;
        }
        return 1;
    }

    // The identity `cert` stands for, or std::system_error(EACCES).
    rawtls::SpiffeId _check_peer(x509_st* cert) const {
        if (X509_check_ca(cert) != 0) {
            refuse("the certificate is a CA");
        }

        // Absent extended key usage is not "any": the certificate must say it
        // may be used for the end of the connection it is on.
        uint32_t usage = X509_get_extended_key_usage(cert);
        uint32_t needed =
            _mode == rawtls::Mode::client ? XKU_SSL_SERVER : XKU_SSL_CLIENT;
        if (usage == UINT32_MAX || !(usage & needed)) {
            refuse("the certificate lacks the extended key usage");
        }

        GENERAL_NAMES* names = static_cast<GENERAL_NAMES*>(
            X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr)
        );
        if (names == nullptr) {
            refuse("the certificate has no subject alternative name");
        }
        std::string uri;
        int uris = 0;
        bool embedded_nul = false;
        for (int i = 0; i < sk_GENERAL_NAME_num(names); ++i) {
            const GENERAL_NAME* name = sk_GENERAL_NAME_value(names, i);
            if (name->type != GEN_URI) {
                continue;
            }
            ++uris;
            const ASN1_IA5STRING* value = name->d.uniformResourceIdentifier;
            const char* data =
                reinterpret_cast<const char*>(ASN1_STRING_get0_data(value));
            size_t size = static_cast<size_t>(ASN1_STRING_length(value));
            if (memchr(data, 0, size) != nullptr) {
                embedded_nul = true;
            }
            uri.assign(data, size);
        }
        GENERAL_NAMES_free(names);
        if (uris != 1 || embedded_nul) {
            refuse("the certificate must have exactly one URI SAN");
        }

        std::optional<rawtls::SpiffeId> parsed;
        try {
            parsed.emplace(uri);
        } catch (const std::system_error&) {
            refuse("the URI SAN is not a rawstor SPIFFE ID");
        }
        const rawtls::SpiffeId& id = *parsed;
        if (id.trust_domain() != _trust_domain) {
            refuse("the SPIFFE ID is in another trust domain");
        }
        if (_mode == rawtls::Mode::client) {
            if (!id.is_server()) {
                refuse(
                    "the server's SPIFFE ID is not that of an OST or an MDS"
                );
            }
            if (id.role() != _expected_role) {
                refuse("the server's SPIFFE ID is not of the role expected");
            }
            if (!_expected_peer.empty() && id.uri().str() != _expected_peer) {
                refuse("the server's SPIFFE ID is not the one expected");
            }
        }
        return id;
    }

    // Throws EACCES for a refused peer, EPROTO for any other failure of the
    // TLS call that returned `result`.
    [[noreturn]] void _fail(int result) {
        int error = SSL_get_error(_ssl, result);
        unsigned long first = ERR_peek_error();
        log_errors("TLS");
        if (_verify_failed ||
            (error == SSL_ERROR_SSL &&
             ERR_GET_REASON(first) ==
                 SSL_R_PEER_DID_NOT_RETURN_A_CERTIFICATE)) {
            RAWSTD_THROW_SYSTEM_ERROR(EACCES);
        }
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    // Takes bytes received from the peer.
    void _feed(const void* data, size_t size) {
        const char* p = static_cast<const char*>(data);
        while (size > 0) {
            int n = BIO_write(_rbio, p, chunk(size));
            if (n <= 0) {
                RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
            }
            p += n;
            size -= static_cast<size_t>(n);
        }
    }

    // The number of bytes waiting to be sent to the peer.
    size_t _output_size() const noexcept { return BIO_ctrl_pending(_wbio); }

    // Moves up to `size` bytes waiting to be sent into `buf`, and returns how
    // many.
    size_t _take_output(void* buf, size_t size) noexcept {
        if (size == 0) {
            return 0;
        }
        int n = BIO_read(_wbio, buf, chunk(size));
        return n > 0 ? static_cast<size_t>(n) : 0;
    }

    // Advances the handshake; true once it is complete.
    bool _handshake_step() {
        if (_handshake_done) {
            return true;
        }
        ERR_clear_error();
        int result = SSL_do_handshake(_ssl);
        if (result == 1) {
            // The verify callback ran for every full handshake; a handshake
            // that finished without it has no identity to go by.
            if (!_peer.has_value()) {
                refuse("no identity was established");
            }
            _handshake_done = true;
            return true;
        }
        int error = SSL_get_error(_ssl, result);
        if (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) {
            return false;
        }
        _fail(result);
    }

    // Encrypts all of `data` into the output.
    void _encrypt(const void* data, size_t size) {
        const char* p = static_cast<const char*>(data);
        while (size > 0) {
            ERR_clear_error();
            int n = SSL_write(_ssl, p, chunk(size));
            if (n <= 0) {
                _fail(n);
            }
            p += n;
            size -= static_cast<size_t>(n);
        }
    }

    // Decrypts up to `size` bytes of what was fed. Returns 0 if there is no
    // complete record yet or the peer has closed; _closed tells the two apart.
    size_t _decrypt(void* buf, size_t size) {
        if (size == 0) {
            return 0;
        }
        ERR_clear_error();
        int n = SSL_read(_ssl, buf, chunk(size));
        if (n > 0) {
            return static_cast<size_t>(n);
        }
        int error = SSL_get_error(_ssl, n);
        if (error == SSL_ERROR_WANT_READ) {
            return 0;
        }
        if (error == SSL_ERROR_ZERO_RETURN) {
            _closed = true;
            return 0;
        }
        _fail(n);
    }

    rawstd::Task<void> _write_all(const unsigned char* p, size_t n) {
        while (n > 0) {
            size_t written = 0;
            try {
                written = co_await _queue.send(_fd, p, n, RAWSTD_MSG_NOSIGNAL);
            } catch (...) {
                _broken = true;
                throw;
            }
            if (written == 0) {
                _broken = true;
                RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
            }
            p += written;
            n -= written;
        }
    }

    // Sends what the session has to say. The caller must be the only one
    // writing: holding _write_mutex, or before the Transport is handed out.
    rawstd::Task<void> _flush() {
        if (_broken) {
            RAWSTD_THROW_SYSTEM_ERROR(ECONNABORTED);
        }
        for (;;) {
            size_t n = _output_size();
            if (n == 0) {
                co_return;
            }
            _out.resize(n);
            _take_output(_out.data(), n);
            co_await _write_all(_out.data(), n);
        }
    }

    rawstd::Task<void> _flush_locked() {
        co_await _write_mutex.acquire();
        Release release(_write_mutex);
        co_await _flush();
    }

    // Encrypts the `count` buffers of `iov` and sends them, whole and in
    // order. `iov` must outlive the call.
    rawstd::Task<size_t> _write(const iovec* iov, size_t count) {
        co_await _write_mutex.acquire();
        Release release(_write_mutex);
        size_t total = 0;
        for (size_t i = 0; i < count; ++i) {
            if (iov[i].iov_len > 0) {
                _encrypt(iov[i].iov_base, iov[i].iov_len);
                total += iov[i].iov_len;
            }
        }
        co_await _flush();
        co_return total;
    }

    // Stops the recv in flight and makes the next one fail. A cancel that
    // finds nothing in flight (the reader is between recvs) is remembered for
    // the next.
    void _cancel_receive() noexcept {
        _cancelled = true;
        if (_inflight != nullptr) {
            try {
                _queue.cancel(_inflight);
            } catch (const std::exception& e) {
                rawstd_warning("Failed to cancel event: %s\n", e.what());
            }
        }
    }

    rawstd::Task<void> _run_handshake() {
        std::vector<unsigned char> in(record_size);
        std::exception_ptr error;
        try {
            for (;;) {
                bool done = _handshake_step();
                co_await _flush();
                if (done) {
                    co_return;
                }
                // Registered so the deadline can cancel it.
                rawio::Awaitable<size_t> op =
                    _queue.recv(_fd, in.data(), in.size(), 0);
                _inflight = op.event();
                size_t n = 0;
                try {
                    n = co_await op;
                } catch (...) {
                    _inflight = nullptr;
                    throw;
                }
                _inflight = nullptr;
                if (n == 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
                }
                _feed(in.data(), n);
            }
        } catch (...) {
            error = std::current_exception();
        }
        // A refused handshake leaves an alert for the peer. Failing to send it
        // must not hide why the handshake failed.
        try {
            co_await _flush();
        } catch (...) {
        }
        std::rethrow_exception(error);
    }

    // Ends the handshake if the peer has not finished it in time, by
    // cancelling the recv it is waiting in.
    rawstd::DetachedTask _deadline(unsigned int timeout_ms) {
        rawio::Awaitable<void> timer = _queue.timeout(timeout_ms * 1000u);
        _timer = timer.event();
        try {
            co_await timer;
        } catch (const std::system_error&) {
            // Cancelled: the handshake ended first.
            _timer = nullptr;
            _deadline_finish();
            co_return;
        }
        _timer = nullptr;
        if (_handshaking) {
            _timed_out = true;
            // Everything the handshake has pending on the socket, a send held
            // up by a peer that does not read as much as a recv.
            _cancelled = true;
            try {
                _queue.cancel(_fd);
            } catch (const std::exception& e) {
                rawstd_warning(
                    "Failed to cancel the handshake: %s\n", e.what()
                );
            }
        }
        _deadline_finish();
    }

public:
    // A client gives `expected_peer`, the exact SPIFFE ID it requires of the
    // server, or leaves it empty and gives `expected_role`, ost or mds, to
    // accept any server of that role in the trust domain; one of the two is
    // required (std::system_error(EINVAL) otherwise). A server accepts any
    // peer the rules allow and ignores both.
    TlsTransport(
        rawio::Queue& queue, int fd, rawtls::Context& context,
        rawtls::Mode mode, const std::string& expected_peer,
        std::optional<rawtls::Role> expected_role
    ) :
        _queue(queue),
        _fd(fd),
        _ctx(context.snapshot()),
        _mode(mode),
        _trust_domain(context.trust_domain()),
        _expected_peer(expected_peer) {
        if (mode == rawtls::Mode::client) {
            // A client that knows nothing about whom it is talking to would
            // accept any certificate of the CA.
            if (!expected_peer.empty()) {
                rawtls::SpiffeId id(expected_peer);
                if (!id.is_server()) {
                    RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
                }
                _expected_role = id.role();
            } else if (expected_role.has_value() &&
                       (*expected_role == rawtls::Role::ost ||
                        *expected_role == rawtls::Role::mds)) {
                _expected_role = *expected_role;
            } else {
                RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
            }
        }

        _ssl = SSL_new(_ctx.get());
        if (_ssl == nullptr) {
            log_errors("TLS session");
            RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
        }
        _rbio = BIO_new(BIO_s_mem());
        _wbio = BIO_new(BIO_s_mem());
        if (_rbio == nullptr || _wbio == nullptr) {
            BIO_free(_rbio);
            BIO_free(_wbio);
            SSL_free(_ssl);
            RAWSTD_THROW_SYSTEM_ERROR(ENOMEM);
        }
        // The SSL owns both BIOs from here on.
        SSL_set_bio(_ssl, _rbio, _wbio);
        SSL_set_app_data(_ssl, this);
        SSL_set_verify(
            _ssl, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, _verify
        );
        if (mode == rawtls::Mode::client) {
            SSL_set_connect_state(_ssl);
        } else {
            SSL_set_accept_state(_ssl);
        }
    }

    TlsTransport(const TlsTransport&) = delete;
    TlsTransport& operator=(const TlsTransport&) = delete;

    ~TlsTransport() override;

    // Runs the handshake within `timeout_ms`. Throws ETIMEDOUT if the deadline
    // is what ended it.
    rawstd::Task<void> handshake(unsigned int timeout_ms) {
        _deadline(timeout_ms);
        rawstd::DetachedTask::rethrow_if_pending();

        std::exception_ptr error;
        try {
            co_await _run_handshake();
        } catch (...) {
            error = std::current_exception();
        }
        _handshaking = false;
        if (_timer != nullptr) {
            try {
                _queue.cancel(_timer);
            } catch (const std::exception& e) {
                rawstd_warning("Failed to cancel event: %s\n", e.what());
            }
        }
        // The deadline touches this object until it is done.
        co_await DeadlineOver{*this};
        if (error) {
            if (_timed_out) {
                RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
            }
            std::rethrow_exception(error);
        }
        // The deadline's cancel is not the stream's: a stream starts afresh.
        _cancelled = false;
    }

    rawstd::Task<size_t>
    send(const void* buf, size_t size, unsigned int) override {
        iovec iov{const_cast<void*>(buf), size};
        co_return co_await _write(&iov, 1);
    }

    rawstd::Task<size_t> sendmsg(const msghdr* msg, unsigned int) override {
        return _write(msg->msg_iov, static_cast<size_t>(msg->msg_iovlen));
    }

    rawio::RecvStream
    recv_multishot(size_t, unsigned int, size_t, unsigned int) override;

    void cancel_recv_multishot() noexcept override { _cancel_receive(); }

    const rawtls::SpiffeId* peer() const noexcept override {
        return &*_peer;
    }
};

/*
 * The decrypted bytes of a connection, handed out like rawio's own receive
 * stream: next(want) completes with exactly `want` bytes once that many have
 * arrived. Nothing is read from the socket unless someone is waiting for it,
 * so a consumer that is busy leaves the data in the socket's buffer.
 */
class TlsRecv final : public rawio::RecvStream::Backend,
                      public std::enable_shared_from_this<TlsRecv> {
private:
    // Null once the Transport is gone: the stream may be read, and dropped,
    // after it.
    TlsTransport* _t;
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
        if (_t == nullptr) {
            _fail(ECANCELED);
            return;
        }
        try {
            for (;;) {
                size_t n = _t->_decrypt(_scratch.data(), _scratch.size());
                if (n == 0) {
                    break;
                }
                _plain.insert(
                    _plain.end(), _scratch.begin(), _scratch.begin() + n
                );
            }
            if (_t->_closed) {
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
        if (_t == nullptr || _t->_cancelled) {
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
        for (;;) {
            if (self->_t == nullptr || self->_t->_cancelled) {
                self->_fail(ECANCELED);
            } else {
                try {
                    TlsTransport& s = *self->_t;
                    rawio::Awaitable<size_t> op = s._queue.recv(
                        s._fd, self->_cipher.data(), self->_cipher.size(), 0
                    );
                    s._inflight = op.event();
                    size_t n = 0;
                    try {
                        n = co_await op;
                    } catch (...) {
                        // The Transport may have been destroyed while the
                        // recv was in flight.
                        if (self->_t != nullptr) {
                            self->_t->_inflight = nullptr;
                        }
                        throw;
                    }
                    if (self->_t == nullptr) {
                        self->_fail(ECANCELED);
                    } else {
                        self->_t->_inflight = nullptr;
                        if (n == 0) {
                            self->_fail(EPIPE);
                        } else {
                            self->_t->_feed(self->_cipher.data(), n);
                        }
                    }
                } catch (const std::system_error& e) {
                    self->_fail(e.code().value());
                }
                self->_decrypt_buffered();
                // A key update the peer asked for, or an alert, waits in the
                // output.
                if (self->_terminal == 0 && self->_t->_output_size() > 0) {
                    try {
                        co_await self->_t->_flush_locked();
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
    explicit TlsRecv(TlsTransport& transport) :
        _t(&transport),
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

    // The Transport is being destroyed.
    void orphan() noexcept { _t = nullptr; }

    void close() noexcept override { cancel(); }

    void cancel() noexcept override {
        if (_t != nullptr) {
            _t->_cancel_receive();
        }
    }

    rawio::Event* event() const noexcept override {
        return const_cast<TlsRecv*>(this);
    }
};


rawio::RecvStream
TlsTransport::recv_multishot(size_t, unsigned int, size_t, unsigned int) {
    _cancelled = false;
    std::shared_ptr<TlsRecv> recv = std::make_shared<TlsRecv>(*this);
    _recv = recv;
    return rawio::RecvStream(std::move(recv));
}

TlsTransport::~TlsTransport() {
    // The recv in flight, if any, ends on its own; the stream no longer
    // reaches this object.
    _cancel_receive();
    std::shared_ptr<TlsRecv> recv = _recv.lock();
    if (recv != nullptr) {
        recv->orphan();
    }
    SSL_free(_ssl);
}

} // namespace

namespace rawtls {

std::unique_ptr<Transport> Transport::plain(rawio::Queue& queue, int fd) {
    return std::make_unique<PlainTransport>(queue, fd);
}

rawstd::Task<std::unique_ptr<Transport>> Transport::tls(
    rawio::Queue& queue, int fd, Context& context, Mode mode,
    const std::string& expected_peer, std::optional<Role> expected_role,
    unsigned int handshake_timeout_ms
) {
    std::unique_ptr<TlsTransport> transport = std::make_unique<TlsTransport>(
        queue, fd, context, mode, expected_peer, expected_role
    );
    co_await transport->handshake(handshake_timeout_ms);
    co_return transport;
}

} // namespace rawtls
