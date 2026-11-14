#ifndef RAWSTOR_MDS_CLIENT_HPP
#define RAWSTOR_MDS_CLIENT_HPP

#include "store.hpp"

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawio/stream.hpp>

#include <rawtls/transport.hpp>

#include <rawstd/coro.hpp>

#include <memory>

namespace rawstor {
namespace mdsserver {

class Server;

// One MDS client connection. Same framing as an OST connection (shared
// `rstr` magic and frame heads, docs/mds.md "Wire protocol") --
// the object opcode group (CMD_OBJ_*) and LOCATION_INFO are served here; every
// other opcode answers -ENOSYS (a plain rawstor-ost, or an OST doubling as
// partial MDS, serves the session/data/shared-metadata groups instead).
// Unlike ost::Client, request handling calls straight into ObjectStore's
// synchronous API -- no per-request async I/O beyond the socket read/
// write itself, so this needs none of ost::Client's ring-buffer multishot
// recv machinery: MDS traffic is low-rate control-plane only
// (docs/mds.md, "Principles" -- "MDS is off the hot path"), and a
// plain sequential single-shot recv loop is simpler and entirely adequate.
class Client final : public std::enable_shared_from_this<Client> {
private:
    struct Private {
        explicit Private() = default;
    };

    RawIOQueue* _queue;
    Server& _server;
    int _fd;
    // The connection's bytes, plain or through TLS.
    std::unique_ptr<rawtls::Transport> _transport;
    // Set by HANDSHAKE, the first request: nothing is served before it.
    bool _handshaken = false;

    static rawstd::DetachedTask _recv_pump(std::weak_ptr<Client> weak);

    // `stream` is the connection's request stream, owned by _recv_pump().
    static rawstd::Task<void> _dispatch(
        std::weak_ptr<Client> weak, const RawstorFrameHead& head,
        rawio::RecvStream& stream
    );

    rawstd::Task<void> _send_response(
        RawstorCommandType type, uint16_t cid, int32_t res,
        const void* data = nullptr, size_t size = 0
    );

public:
    // `transport` is the connection on `fd`, after any TLS handshake.
    static rawstd::Task<std::shared_ptr<Client>> create(
        RawIOQueue* queue, Server& server, int fd,
        std::unique_ptr<rawtls::Transport> transport
    );

    Client(
        Private, RawIOQueue* queue, Server& server, int fd,
        std::unique_ptr<rawtls::Transport> transport
    );
    Client(const Client&) = delete;
    Client(Client&&) = delete;
    ~Client();

    Client& operator=(const Client&) = delete;
    Client& operator=(Client&&) = delete;
};

} // namespace mdsserver
} // namespace rawstor

#endif // RAWSTOR_MDS_CLIENT_HPP
