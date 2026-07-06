#ifndef RAWSTOR_OSTBACKEND_SESSION_HPP
#define RAWSTOR_OSTBACKEND_SESSION_HPP

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <memory>
#include <vector>

namespace rawstor {
namespace ostbackend {

class Server;

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
        RawstorOSTFrameAllocateBody alloc;
        RawstorOSTFrameIOBody io;
        RawstorOSTFrameMetaBody meta;
    } _request_body;
    RawstorObject* _object;

    /*
     * SET_OBJECT (the handshake) was received: it must be the first
     * command on every connection, anything else before it is a protocol
     * violation (the misconnection guard).
     */
    bool _handshaken;

    /*
     * Expires on session destruction; async operation completions check it
     * before touching _fd, which may be closed or reused by then.
     */
    std::shared_ptr<int> _alive;

    /* An object open is in flight; concurrent SET_OBJECT gets EBUSY. */
    bool _open_pending;

    static int
    _open_complete(RawstorObject* object, int result, void* data) noexcept;

    static ssize_t _recv(
        const iovec* iov, unsigned int niov, size_t result, int error,
        void* data
    ) noexcept;
    ssize_t
    _recv(const iovec* iov, unsigned int niov, size_t result, int error);
    ssize_t _recv_head(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_body(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_data(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_ignore(const iovec* iov, unsigned int niov, size_t result);
    void _allocate(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameAllocateBody& body
    );
    void _release(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _set_object(
        const RawstorOSTFrameHead& head,
        const RawstorOSTFrameSetObjectBody& body
    );
    void
    _read(const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body);
    void _write(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body,
        const iovec* iov, unsigned int niov, size_t size
    );
    void _discard(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
    );
    void _spec(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _set_state(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameMetaBody& body
    );
    void
    _flush(const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body);
    void _unknown(const RawstorOSTFrameHead& head);

    /* Send a final response, then close the session once it is flushed. */
    void _close_after_response(const RawstorOSTFrameHead& head, int32_t res);

    std::vector<rawstd::URI> _targets(const RawstdUUID& uuid);

public:
    Session(RawIOQueue* queue, Server& server, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session() noexcept;

    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SESSION_HPP
