#ifndef RAWSTOR_MDSBACKEND_SESSION_HPP
#define RAWSTOR_MDSBACKEND_SESSION_HPP

#include "store.hpp"

#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <sys/uio.h>

#include <memory>

namespace rawstor {
namespace mdsbackend {

class Server;

/*
 * One MDS client connection. Same framing as the OST session; the role
 * subset differs: session (SET_OBJECT, null binding only) + volume
 * commands. Everything else — data opcodes, and the witness subset until
 * stage 3 — answers -ENOSYS (rawstor_docs/Mds.md, role matrix).
 */
class Session final {
private:
    RawIOQueue* _queue;
    Server& _server;
    int _fd;
    RawIOEvent* _recv_event;
    ssize_t (Session::*_next)(const iovec*, unsigned int, size_t);
    RawstorOSTFrameHead _request_head;
    union {
        RawstorOSTFrameBasicBody basic;
        RawstorOSTFrameSetObjectBody setobj;
        RawstorVolCreateBody vol_create;
    } _request_body;

    /* SET_OBJECT (the handshake) was received on this connection. */
    bool _handshaken;

    std::shared_ptr<int> _alive;

    static ssize_t _recv(
        const iovec* iov, unsigned int niov, size_t result, int error,
        void* data
    ) noexcept;
    ssize_t
    _recv(const iovec* iov, unsigned int niov, size_t result, int error);
    ssize_t _recv_head(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_body(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_ignore(const iovec* iov, unsigned int niov, size_t result);

    void _set_object(
        const RawstorOSTFrameHead& head,
        const RawstorOSTFrameSetObjectBody& body
    );
    void _vol_create(
        const RawstorOSTFrameHead& head, const RawstorVolCreateBody& body
    );
    void _vol_open(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _vol_resize(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _vol_remove(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );

    /* Send a final response, then close the session once it is flushed. */
    void _close_after_response(const RawstorOSTFrameHead& head, int32_t res);

public:
    Session(RawIOQueue* queue, Server& server, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session() noexcept;

    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
};

} // namespace mdsbackend
} // namespace rawstor

#endif // RAWSTOR_MDSBACKEND_SESSION_HPP
