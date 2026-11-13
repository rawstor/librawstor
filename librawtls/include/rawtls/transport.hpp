#ifndef RAWTLS_TRANSPORT_HPP
#define RAWTLS_TRANSPORT_HPP

#include <rawtls/context.hpp>
#include <rawtls/op.hpp>
#include <rawtls/session.hpp>
#include <rawtls/spiffe.hpp>

#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

#include <rawstd/coro.hpp>

#include <memory>
#include <string>

#include <sys/socket.h>

namespace rawtls {

/*
 * One connected socket, as the code that speaks the wire protocol sees it:
 * what to send, a stream of what arrived, and a way to stop that stream. A
 * plain Transport hands every call to the Queue as it is; a TLS Transport
 * carries the same bytes through a Session, so the code above it is the same
 * with and without TLS.
 *
 * The Transport does not own the socket and does not close it. It must not be
 * used from more than one thread, like the Queue it was made for.
 */
class Transport {
public:
    virtual ~Transport() = default;

    // A connection that carries its bytes as they are.
    static std::unique_ptr<Transport> plain(rawio::Queue& queue, int fd);

    // A TLS connection: runs the handshake on `fd` as the client or the
    // server and returns the Transport once the peer is verified. A client
    // names the server it expects, as Session does. Throws what Session
    // throws, or the std::system_error of the socket.
    static rawstd::Task<std::unique_ptr<Transport>>
    tls(rawio::Queue& queue, int fd, Context& context, Session::Mode mode,
        const std::string& expected_peer = "");

    // Sends all of `buf` (or all of `msg`) and completes with the number of
    // bytes of it. Sends on one Transport reach the peer whole and in the
    // order they were started.
    virtual Op<size_t>
    send(const void* buf, size_t size, unsigned int flags) = 0;
    virtual Op<size_t> sendmsg(const msghdr* msg, unsigned int flags) = 0;

    /*
     * What the peer sent, as items of exactly the size asked for with next(),
     * like rawio::Queue::recv_multishot(). On a plain connection the ring
     * is `entries` buffers of `entry_size`; a TLS connection reads as much as
     * it is given and ignores both. There is one stream per Transport.
     */
    virtual rawio::RecvStream recv_multishot(
        size_t entry_size, unsigned int entries, size_t size, unsigned int flags
    ) = 0;

    // Stops the stream above: its pending next() fails with ECANCELED.
    // `event` is the stream's event().
    virtual Op<void> cancel_receive(rawio::Event* event) = 0;

    // The identity of the peer, null on a plain connection.
    virtual const SpiffeId* peer() const noexcept = 0;
};

} // namespace rawtls

#endif // RAWTLS_TRANSPORT_HPP
