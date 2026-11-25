#include <rawtls/authorization.hpp>
#include <rawtls/transport.hpp>

#include <rawtls/context.hpp>
#include <rawtls/spiffe.hpp>

#include <rawio/awaitable.hpp>
#include <rawio/with_timeout.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <algorithm>
#include <cerrno>
#include <climits>
#include <coroutine>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <deque>
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

// What every Transport that writes to a socket has in common: one writer at a
// time, so that what a call sends goes out whole before the next call's bytes
// and the frames of the stream keep their boundaries; and a connection that is
// broken once a failed write has left half a frame in the stream.
//
// Sends do not wait for each other's syscalls. A send is queued; the writer
// takes everything queued at that moment as one batch and puts it on the wire
// with one write, so that a burst of small requests costs one syscall and, on
// TLS, a few records instead of one of each per request. While a batch is on
// its way, the sends that arrive form the next one.
class SerialTransport : public rawtls::Transport {
public:
    // A send that has been handed to the writer.
    struct Frame {
        const msghdr* msg;
        unsigned int flags;
        size_t size;
        std::exception_ptr error;
        bool done = false;
        std::coroutine_handle<> waiter;

        Frame(const msghdr* msg, unsigned int flags) noexcept :
            msg(msg),
            flags(flags),
            size(rawstd_iovec_size(
                msg->msg_iov, static_cast<unsigned int>(msg->msg_iovlen)
            )) {}
    };

private:
    // The most the writer puts into one batch: enough to turn a burst into a
    // single syscall, little enough not to keep the first send of the batch
    // waiting for a megabyte of the others.
    static constexpr size_t max_batch_frames = 256;
    static constexpr size_t max_batch_bytes = 1 << 20;
    static constexpr size_t max_batch_iov = 1024;

    class Awaiter final {
    private:
        Frame& _frame;

    public:
        explicit Awaiter(Frame& frame) noexcept : _frame(frame) {}
        bool await_ready() const noexcept { return _frame.done; }
        void await_suspend(std::coroutine_handle<> h) noexcept {
            _frame.waiter = h;
        }
        size_t await_resume() const {
            if (_frame.error) {
                std::rethrow_exception(_frame.error);
            }
            return _frame.size;
        }
    };

    // What the writer shares with its Transport. The writer is resuming the
    // senders when the last of them may let go of the Transport, and so it
    // outlives it for that moment: it must be able to tell, and to stop
    // without touching the Transport.
    struct Writer {
        std::deque<Frame*> queue;
        bool running = false;
        bool alive = true;
    };

    std::shared_ptr<Writer> _writer = std::make_shared<Writer>();

    // A message that carries an address or ancillary data goes out on its own:
    // those belong to one sendmsg() of the message.
    static bool _solo(const msghdr* msg) noexcept {
        return msg->msg_name != nullptr || msg->msg_control != nullptr;
    }

    // Takes the frames at the head of the queue that go out in one write.
    static void _take_batch(Writer& writer, std::vector<Frame*>& batch) {
        size_t bytes = 0;
        size_t iov = 0;
        while (!writer.queue.empty()) {
            Frame* frame = writer.queue.front();
            if (!batch.empty()) {
                if (batch.size() >= max_batch_frames ||
                    bytes + frame->size > max_batch_bytes ||
                    iov + frame->msg->msg_iovlen > max_batch_iov ||
                    frame->flags != batch.front()->flags || _solo(frame->msg) ||
                    _solo(batch.front()->msg)) {
                    break;
                }
            }
            bytes += frame->size;
            iov += frame->msg->msg_iovlen;
            batch.push_back(frame);
            writer.queue.pop_front();
        }
    }

    // Sends what is queued, a batch at a time, until nothing is left.
    // Everything it touches is in `writer`, except while a batch is on its
    // way: the Transport must not be destroyed then, as for any send.
    static rawstd::DetachedTask
    _write_loop(SerialTransport* self, std::shared_ptr<Writer> writer) {
        std::vector<Frame*> batch;
        std::vector<std::coroutine_handle<>> woken;
        while (!writer->queue.empty()) {
            batch.clear();
            _take_batch(*writer, batch);
            std::exception_ptr error;
            if (self->_broken) {
                try {
                    RAWSTD_THROW_SYSTEM_ERROR(ECONNABORTED);
                } catch (...) {
                    error = std::current_exception();
                }
            } else {
                try {
                    co_await self->_send_batch(batch);
                } catch (...) {
                    error = std::current_exception();
                }
            }
            // The senders are resumed once the whole batch is settled: what
            // they send next joins the queue, behind what is already there.
            woken.clear();
            for (Frame* frame : batch) {
                if (!frame->done) {
                    frame->error = error;
                    frame->done = true;
                }
                if (frame->waiter) {
                    woken.push_back(frame->waiter);
                }
            }
            for (std::coroutine_handle<> h : woken) {
                h.resume();
            }
            if (!writer->alive) {
                // The last sender let go of the Transport.
                co_return;
            }
        }
        writer->running = false;
    }

protected:
    // Set by a transport whose write failed after a part of its bytes went
    // out: nothing may follow that half frame, and the sends waiting their
    // turn fail instead of writing to a socket that is being closed.
    bool _broken = false;

    // Sends all of the frames of `batch`, in order, and marks each one done as
    // soon as all its bytes are out (the writer completes the frames that are
    // not done when this throws, with the error). All frames have the same
    // flags and a frame of a batch of several has neither address nor
    // ancillary data. The messages stay alive until this completes.
    virtual rawstd::Task<void>
    _send_batch(const std::vector<Frame*>& batch) = 0;

public:
    ~SerialTransport() override { _writer->alive = false; }

    rawstd::Task<size_t>
    send(const void* buf, size_t size, unsigned int flags) final {
        iovec iov{const_cast<void*>(buf), size};
        msghdr msg{};
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        co_return co_await _enqueue(&msg, flags);
    }

    rawstd::Task<size_t> sendmsg(const msghdr* msg, unsigned int flags) final {
        return _enqueue(msg, flags);
    }

private:
    rawstd::Task<size_t> _enqueue(const msghdr* msg, unsigned int flags) {
        if (_broken) {
            RAWSTD_THROW_SYSTEM_ERROR(ECONNABORTED);
        }
        Frame frame(msg, flags);
        _writer->queue.push_back(&frame);
        if (!_writer->running) {
            _writer->running = true;
            _write_loop(this, _writer);
            rawstd::DetachedTask::rethrow_if_pending();
        }
        co_return co_await Awaiter(frame);
    }
};

class PlainTransport final : public SerialTransport {
private:
    rawio::Queue& _queue;
    int _fd;
    rawio::RecvStream::Canceller _recv;
    // The iovecs of the batch, gathered into one array. Kept between batches
    // so that a busy connection does not allocate for each.
    std::vector<iovec> _gather;

    // Sends the frames of the batch with as few sendmsg() calls as the socket
    // takes: usually one. A short send of the socket is continued from where
    // it stopped; the vectors of the messages are left as they are.
    rawstd::Task<void> _send_batch(const std::vector<Frame*>& batch) override {
        iovec* iov;
        unsigned int niov;
        msghdr part;
        size_t total = 0;
        if (batch.size() == 1) {
            // Nothing to gather, and the message may carry an address or
            // ancillary data that only it can describe.
            part = *batch.front()->msg;
            iov = part.msg_iov;
            niov = static_cast<unsigned int>(part.msg_iovlen);
            total = batch.front()->size;
        } else {
            _gather.clear();
            for (const Frame* frame : batch) {
                const msghdr* msg = frame->msg;
                _gather.insert(
                    _gather.end(), msg->msg_iov, msg->msg_iov + msg->msg_iovlen
                );
                total += frame->size;
            }
            part = {};
            iov = _gather.data();
            niov = static_cast<unsigned int>(_gather.size());
            part.msg_iov = iov;
            part.msg_iovlen = niov;
        }
        const unsigned int flags = batch.front()->flags;
        std::vector<iovec> rest;
        // The vectors of a single message are not ours to change.
        bool own = batch.size() != 1;
        size_t sent = 0;
        size_t completed = 0;
        size_t frame_end = 0;
        try {
            while (sent < total) {
                size_t n = co_await _queue.sendmsg(_fd, &part, flags);
                if (n == 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
                }
                sent += n;
                // Frames that are out whole are done, whatever happens to the
                // ones behind them.
                while (completed < batch.size() &&
                       frame_end + batch[completed]->size <= sent) {
                    frame_end += batch[completed]->size;
                    batch[completed]->done = true;
                    ++completed;
                }
                // Ancillary data goes out with the first bytes of a message:
                // what continues it carries none, or the peer would get it
                // again.
                part.msg_control = nullptr;
                part.msg_controllen = 0;
                if (sent < total) {
                    if (!own) {
                        rest.assign(iov, iov + niov);
                        iov = rest.data();
                        own = true;
                    }
                    rawstd_iovec_discard_front(&iov, &niov, n);
                    part.msg_iov = iov;
                    part.msg_iovlen = niov;
                }
            }
        } catch (...) {
            if (sent > 0) {
                _broken = true;
            }
            throw;
        }
    }

public:
    PlainTransport(rawio::Queue& queue, int fd) noexcept :
        _queue(queue),
        _fd(fd) {}

    ~PlainTransport() override { cancel_recv_multishot(); }

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
    uint64_t peer_expiry() const noexcept override { return 0; }
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
class TlsTransport final : public SerialTransport {
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
    rawtls::Type _expected_type = rawtls::Type::ost;
    std::optional<rawtls::SpiffeId> _peer;
    uint64_t _peer_expiration = 0;
    uint64_t _local_expiration = 0;
    bool _handshake_done = false;
    bool _verify_failed = false;
    // True once the peer has said it will send no more.
    bool _closed = false;
    std::vector<unsigned char> _out;
    // The stream handed out last, the one cancel_recv_multishot() stops.
    std::weak_ptr<TlsRecv> _recv;
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
    rawtls::SpiffeId _check_peer(x509_st* cert, bool own = false) const {
        if (X509_check_ca(cert) != 0) {
            refuse("the certificate is a CA");
        }

        // Absent extended key usage is not "any": the certificate must say it
        // may be used for the end of the connection it is on.
        uint32_t usage = X509_get_extended_key_usage(cert);
        uint32_t needed = (_mode == rawtls::Mode::client) != own
                              ? XKU_SSL_SERVER
                              : XKU_SSL_CLIENT;
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
        if (!own && id.trust_domain() != _trust_domain) {
            refuse("the SPIFFE ID is in another trust domain");
        }
        if (!own && _mode == rawtls::Mode::client) {
            if (!id.is_server()) {
                refuse(
                    "the server's SPIFFE ID is not that of an OST or an MDS"
                );
            }
            if (id.type() != _expected_type) {
                refuse("the server's SPIFFE ID is not of the type expected");
            }
            if (!_expected_peer.empty() && id.uri().str() != _expected_peer) {
                refuse("the server's SPIFFE ID is not the one expected");
            }
        }
        parsed->permissions(rawtls::certificate_permissions(cert));
        if (id.type() != rawtls::Type::client &&
            (id.permissions().role || !id.permissions().objects.empty())) {
            refuse("only account clients may carry permissions");
        }
        return *parsed;
    }

    // Throws EACCES for a refused peer, EPROTO for any other failure of the
    // TLS call that returned `result`.
    [[noreturn]] void _fail(int result) {
        int error = SSL_get_error(_ssl, result);
        unsigned long first = ERR_peek_error();
        log_errors("TLS");
        if (_verify_failed || (error == SSL_ERROR_SSL &&
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
            struct tm expiry{};
            X509* peer_cert = SSL_get0_peer_certificate(_ssl);
            if (peer_cert &&
                ASN1_TIME_to_tm(X509_get0_notAfter(peer_cert), &expiry) == 1) {
                time_t epoch = timegm(&expiry);
                if (epoch > 0) {
                    _peer_expiration = static_cast<uint64_t>(epoch);
                }
            }
            X509* own = SSL_get_certificate(_ssl);
            (void)_check_peer(own, true);
            if (ASN1_TIME_to_tm(X509_get0_notAfter(own), &expiry) == 1) {
                time_t epoch = timegm(&expiry);
                if (epoch > 0) {
                    _local_expiration = static_cast<uint64_t>(epoch);
                }
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
    // writing: inside _send_locked(), or before the Transport is handed out.
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

    // Plaintext waiting for a record: the small buffers of a batch share
    // records instead of making one each.
    std::vector<unsigned char> _stage;

    void _stage_flush() {
        if (!_stage.empty()) {
            _encrypt(_stage.data(), _stage.size());
            _stage.clear();
        }
    }

    // Encrypts `data` after what is staged: what is staged is filled up to a
    // record first, then a buffer that is not smaller than a record goes
    // straight to the session, and any other one waits with its neighbours
    // until they fill a record.
    void _encrypt_staged(const void* data, size_t size) {
        const unsigned char* p = static_cast<const unsigned char*>(data);
        if (!_stage.empty()) {
            size_t n = std::min(size, record_size - _stage.size());
            _stage.insert(_stage.end(), p, p + n);
            p += n;
            size -= n;
            if (_stage.size() < record_size) {
                return;
            }
            _stage_flush();
        }
        if (size >= record_size) {
            _encrypt(p, size);
        } else {
            _stage.insert(_stage.end(), p, p + size);
        }
    }

    // Encrypts the buffers of the messages of the batch, in order, and sends
    // them with one write: the records of the whole batch go out together.
    // A batch takes the writer from encrypting until the last byte of its
    // records is out.
    rawstd::Task<void> _send_batch(const std::vector<Frame*>& batch) override {
        // Reconnect with the reloaded credentials before sending an expired
        // certificate's command; the server's EACCES is a permanent IO error.
        if (_mode == rawtls::Mode::client &&
            _local_expiration <= static_cast<uint64_t>(time(nullptr))) {
            RAWSTD_THROW_SYSTEM_ERROR(ECONNRESET);
        }
        try {
            _stage.reserve(record_size);
            for (const Frame* frame : batch) {
                const iovec* iov = frame->msg->msg_iov;
                size_t count = static_cast<size_t>(frame->msg->msg_iovlen);
                for (size_t i = 0; i < count; ++i) {
                    if (iov[i].iov_len > 0) {
                        _encrypt_staged(iov[i].iov_base, iov[i].iov_len);
                    }
                }
            }
            _stage_flush();
        } catch (...) {
            // A session that failed to encrypt is of no use: what went into
            // it before is not going to reach the peer as a whole.
            _stage.clear();
            _broken = true;
            throw;
        }
        co_await _flush();
        for (Frame* frame : batch) {
            frame->done = true;
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
                size_t n = co_await _queue.recv(_fd, in.data(), in.size(), 0);
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

public:
    // A client gives `expected_peer`, the exact SPIFFE ID it requires of the
    // server, or leaves it empty and gives `expected_type`, ost or mds, to
    // accept any server of that type in the trust domain; one of the two is
    // required (std::system_error(EINVAL) otherwise). A server accepts any
    // peer the rules allow and ignores both.
    TlsTransport(
        rawio::Queue& queue, int fd, rawtls::Context& context,
        rawtls::Mode mode, const std::string& expected_peer,
        std::optional<rawtls::Type> expected_type
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
                _expected_type = id.type();
            } else if (expected_type.has_value() &&
                       (*expected_type == rawtls::Type::ost ||
                        *expected_type == rawtls::Type::mds)) {
                _expected_type = *expected_type;
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

    // Runs the handshake within `timeout_ms`. Throws ETIMEDOUT if it takes
    // longer.
    rawstd::Task<void> handshake(unsigned int timeout_ms) {
        co_await rawio::with_timeout(
            _queue, timeout_ms * 1000u, _run_handshake()
        );
    }

    rawio::RecvStream
    recv_multishot(size_t, unsigned int, size_t, unsigned int) override;

    void cancel_recv_multishot() noexcept override;

    const rawtls::SpiffeId* peer() const noexcept override { return &*_peer; }
    uint64_t peer_expiry() const noexcept override { return _peer_expiration; }
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
    rawio::Queue& _queue;
    // The recv in flight, if any, and whether the stream was told to stop. A
    // cancel that finds nothing in flight (the reader is between recvs) is
    // remembered for the next. They belong to this stream, not to the
    // Transport: the stream that replaces it is not stopped by what is done
    // to this one, as it is when the receive ring of a connection is replaced
    // and the old stream is destroyed after the new one is started.
    rawio::Event* _inflight = nullptr;
    bool _cancelled = false;
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
        if (_t == nullptr || _cancelled) {
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
            if (self->_t == nullptr || self->_cancelled) {
                self->_fail(ECANCELED);
            } else {
                try {
                    rawio::Awaitable<size_t> op = self->_queue.recv(
                        self->_t->_fd, self->_cipher.data(),
                        self->_cipher.size(), 0
                    );
                    self->_inflight = op.event();
                    size_t n = 0;
                    try {
                        n = co_await op;
                    } catch (...) {
                        self->_inflight = nullptr;
                        throw;
                    }
                    self->_inflight = nullptr;
                    // The Transport may have been destroyed while the recv was
                    // in flight.
                    if (self->_t == nullptr) {
                        self->_fail(ECANCELED);
                    } else {
                        if (n == 0) {
                            self->_fail(EPIPE);
                        } else {
                            self->_t->_feed(self->_cipher.data(), n);
                        }
                    }
                } catch (const std::system_error& e) {
                    self->_fail(e.code().value());
                }
                // What decrypting leaves to say, a key update the peer asked
                // for or an alert, stays in the output until the next send
                // puts it ahead of its own records: the answer to a key
                // update is due before the next application data, not at
                // once (RFC 8446, 4.6.3). The stream writes nothing, so it
                // never holds the Transport across a send.
                self->_decrypt_buffered();
            }
            if (self->_deliver()) {
                co_return;
            }
        }
    }

public:
    explicit TlsRecv(TlsTransport& transport) :
        _t(&transport),
        _queue(transport._queue),
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
        _cancelled = true;
        if (_inflight != nullptr) {
            try {
                _queue.cancel(_inflight);
            } catch (const std::exception& e) {
                rawstd_warning("Failed to cancel event: %s\n", e.what());
            }
        }
    }

    rawio::Event* event() const noexcept override {
        return const_cast<TlsRecv*>(this);
    }
};

rawio::RecvStream
TlsTransport::recv_multishot(size_t, unsigned int, size_t, unsigned int) {
    std::shared_ptr<TlsRecv> recv = std::make_shared<TlsRecv>(*this);
    _recv = recv;
    return rawio::RecvStream(std::move(recv));
}

void TlsTransport::cancel_recv_multishot() noexcept {
    std::shared_ptr<TlsRecv> recv = _recv.lock();
    if (recv != nullptr) {
        recv->cancel();
    }
}

TlsTransport::~TlsTransport() {
    // The recv in flight, if any, ends on its own; the stream no longer
    // reaches this object.
    std::shared_ptr<TlsRecv> recv = _recv.lock();
    if (recv != nullptr) {
        recv->cancel();
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
    const std::string& expected_peer, std::optional<Type> expected_type,
    unsigned int handshake_timeout_ms
) {
    std::unique_ptr<TlsTransport> transport = std::make_unique<TlsTransport>(
        queue, fd, context, mode, expected_peer, expected_type
    );
    co_await transport->handshake(handshake_timeout_ms);
    co_return transport;
}

} // namespace rawtls
