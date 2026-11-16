#ifndef RAWTLS_TRANSPORT_HPP
#define RAWTLS_TRANSPORT_HPP

#include <rawtls/context.hpp>
#include <rawtls/spiffe.hpp>

#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

#include <rawstd/coro.hpp>

#include <memory>
#include <optional>
#include <string>

#include <sys/socket.h>

namespace rawtls {

enum class Mode {
    client,
    server,
};

/*
 * One connected socket, as the code that speaks the wire protocol sees it:
 * what to send, a stream of what arrived, and a way to stop that stream. A
 * plain Transport hands every call to the Queue as it is; a TLS Transport
 * carries the same bytes through a TLS 1.3 connection, so the code above it is
 * the same with and without TLS.
 *
 * The Transport does not own the socket and does not close it. It must not be
 * used from more than one thread, like the Queue it was made for.
 */
class Transport {
public:
    virtual ~Transport() = default;

    // A connection that carries its bytes as they are.
    static std::unique_ptr<Transport> plain(rawio::Queue& queue, int fd);

    /*
     * A TLS connection: runs the handshake on the connected socket `fd` as
     * the client or the server and returns the Transport once the peer is
     * verified.
     *
     * A client gives `expected_peer`, the exact SPIFFE ID it requires of the
     * server, or leaves it empty and gives `expected_role`, ost or mds, to
     * accept any server of that role in the trust domain; one of the two is
     * required (std::system_error(EINVAL) otherwise). A server accepts any
     * peer the rules below allow and ignores both.
     *
     * Both sides verify the other. The peer's certificate must chain to a CA
     * of the Context, have exactly one URI SAN holding a SPIFFE ID of the
     * Context's trust domain, carry the key usage of its end of the
     * connection and not be a CA. A client expects the exact ID of the server
     * when it knows it, otherwise the role (an OST or an MDS) the server must
     * have, and a server's ID must be that of an OST or an MDS either way.
     *
     * Throws std::system_error: EACCES when the peer's certificate or
     * identity is refused, EPROTO for any other TLS error, ETIMEDOUT when the
     * peer has not completed the handshake within `handshake_timeout_ms`, or
     * the error of the socket. In TLS 1.3 the client's handshake completes
     * before the server has checked the client's certificate: a client that
     * is refused learns it from its stream, which fails with EPROTO.
     */
    static rawstd::Task<std::unique_ptr<Transport>>
    tls(rawio::Queue& queue, int fd, Context& context, Mode mode,
        const std::string& expected_peer = "",
        std::optional<Role> expected_role = std::nullopt,
        unsigned int handshake_timeout_ms = 10000);

    // Sends `buf` (or `msg`) and completes with the number of its bytes that
    // went out: a plain connection may send less, like a socket, and a TLS
    // connection always sends all of it. Sends on a TLS Transport reach the
    // peer whole and in the order they were started.
    virtual rawstd::Task<size_t>
    send(const void* buf, size_t size, unsigned int flags) = 0;
    virtual rawstd::Task<size_t>
    sendmsg(const msghdr* msg, unsigned int flags) = 0;

    /*
     * What the peer sent, as items of exactly the size asked for with next(),
     * like rawio::Queue::recv_multishot(). On a plain connection the ring
     * is `entries` buffers of `entry_size`; a TLS connection reads as much as
     * it is given and ignores both. There is one stream per Transport.
     */
    virtual rawio::RecvStream recv_multishot(
        size_t entry_size, unsigned int entries, size_t size, unsigned int flags
    ) = 0;

    // Stops the stream above: its pending next() fails with ECANCELED. Like
    // Queue::cancel(), it only requests the cancellation. Safe at any time:
    // before there is a stream, after it has ended and after it was
    // destroyed. Destroying the Transport does the same, so the stream does
    // not outlive its connection waiting for data.
    virtual void cancel_recv_multishot() noexcept = 0;

    // The identity of the peer, null on a plain connection.
    virtual const SpiffeId* peer() const noexcept = 0;

    virtual uint64_t peer_expiry() const noexcept = 0;
};

} // namespace rawtls

#endif // RAWTLS_TRANSPORT_HPP
