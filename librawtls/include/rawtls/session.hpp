#ifndef RAWTLS_SESSION_HPP
#define RAWTLS_SESSION_HPP

#include <rawtls/context.hpp>
#include <rawtls/spiffe.hpp>

#include <cstddef>
#include <memory>
#include <optional>
#include <string>

struct ssl_st;
struct bio_st;
struct x509_st;
struct x509_store_ctx_st;

namespace rawtls {

/*
 * One TLS 1.3 connection, with no I/O of its own. The transport hands the
 * bytes it received to feed() and sends what take_output() gives back; the
 * Session turns that into a handshake, plaintext in, and plaintext out.
 *
 *     while (!session.handshake()) {
 *         send(session.take_output());
 *         session.feed(receive());
 *     }
 *     send(session.take_output());
 *
 * Every call that changes the state of the connection can leave bytes to send,
 * so take_output() follows each of them. Failures throw std::system_error:
 * EACCES when the peer's certificate or identity is refused, EPROTO for any
 * other TLS error. The bytes of an alert may be waiting in take_output() after
 * a throw; send them, then close the connection.
 *
 * Both sides verify the other. The peer's certificate must chain to a CA of
 * the Context, have exactly one URI SAN holding a SPIFFE ID of the Context's
 * trust domain, carry the key usage of its end of the connection and not be
 * a CA. A client also says whom it expects: the exact ID of the server when it
 * knows it, otherwise the role (an OST or an MDS) the server must have, and a
 * server's ID must be that of an OST or an MDS either way.
 *
 * In TLS 1.3 the client's handshake completes before the server has checked
 * the client's certificate: a client that is refused learns it from the next
 * decrypt().
 */
class Session final {
public:
    enum class Mode {
        client,
        server,
    };

private:
    std::shared_ptr<ssl_ctx_st> _ctx;
    ssl_st* _ssl;
    bio_st* _rbio;
    bio_st* _wbio;
    Mode _mode;
    std::string _trust_domain;
    std::string _expected_peer;
    Role _expected_role;
    std::optional<SpiffeId> _peer;
    bool _handshake_done;
    bool _verify_failed;
    bool _closed;

    static int _verify(int ok, x509_store_ctx_st* store_ctx);

    // Throws EACCES for a refused peer, EPROTO for any other failure of the
    // TLS call that returned `result`.
    [[noreturn]] void _fail(int result);

    // The identity `cert` stands for, or std::system_error(EACCES).
    SpiffeId _check_peer(x509_st* cert) const;

public:
    /*
     * A client gives `expected_peer`, the exact SPIFFE ID it requires of the
     * server, or leaves it empty and gives `expected_role`, ost or mds, to
     * accept any server of that role in the trust domain; one of the two is
     * required (std::system_error(EINVAL) otherwise). A server accepts any
     * peer the rules above allow and ignores both.
     */
    Session(
        Context& context, Mode mode, const std::string& expected_peer = "",
        std::optional<Role> expected_role = std::nullopt
    );
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
    ~Session();

    // Takes bytes received from the peer.
    void feed(const void* data, size_t size);

    // The number of bytes waiting to be sent to the peer.
    size_t output_size() const noexcept;

    // Moves up to `size` bytes waiting to be sent into `buf`, and returns how
    // many.
    size_t take_output(void* buf, size_t size) noexcept;

    // Advances the handshake; true once it is complete.
    bool handshake();

    bool handshake_done() const noexcept { return _handshake_done; }

    // The identity of the peer, once the handshake is complete.
    const SpiffeId& peer() const;

    // Encrypts all of `data` into the output. The handshake must be complete.
    void encrypt(const void* data, size_t size);

    // Decrypts up to `size` bytes of what was fed. Returns 0 if there is no
    // complete record yet or the peer has closed; closed() tells the two
    // apart.
    size_t decrypt(void* buf, size_t size);

    // Queues the close_notify alert.
    void shutdown();

    // True once the peer has said it will send no more.
    bool closed() const noexcept { return _closed; }
};

} // namespace rawtls

#endif // RAWTLS_SESSION_HPP
