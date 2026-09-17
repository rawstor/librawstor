#ifndef RAWSTOR_MDS_SESSION_HPP
#define RAWSTOR_MDS_SESSION_HPP

#include "store.hpp"

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawstd/coro.hpp>

#include <memory>

namespace rawstor {
namespace mds {

class Server;

// One MDS client connection. Same framing as an OST connection (shared
// `rstr` magic and frame heads, docs/mds.md "Wire protocol") --
// only the object opcode group (CMD_OBJ_*) is actually served here; every
// other opcode answers -ENOSYS (a plain rawstor-ost, or an OST doubling as
// partial MDS, serves the session/data/shared-metadata groups instead).
// Unlike ost::Client, request handling calls straight into ObjectStore's
// synchronous API -- no per-request async I/O beyond the socket read/
// write itself, so this needs none of ost::Client's ring-buffer multishot
// recv machinery: MDS traffic is low-rate control-plane only
// (docs/mds.md, "Principles" -- "MDS is off the hot path"), and a
// plain sequential single-shot recv loop is simpler and entirely adequate.
class Session final : public std::enable_shared_from_this<Session> {
private:
    struct Private {
        explicit Private() = default;
    };

    RawIOQueue* _queue;
    Server& _server;
    int _fd;

    static rawstd::DetachedTask _recv_pump(std::weak_ptr<Session> weak);

    static rawstd::Task<void>
    _dispatch(std::weak_ptr<Session> weak, const RawstorOSTFrameHead& head);

    rawstd::Task<void> _send_response(
        RawstorOSTCommandType type, uint16_t cid, int32_t res,
        const void* data = nullptr, size_t size = 0
    );

public:
    static rawstd::Task<std::shared_ptr<Session>>
    create(RawIOQueue* queue, Server& server, int fd);

    Session(Private, RawIOQueue* queue, Server& server, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session();

    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_SESSION_HPP
