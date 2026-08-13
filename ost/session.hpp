#ifndef RAWSTOR_OSTBACKEND_SESSION_HPP
#define RAWSTOR_OSTBACKEND_SESSION_HPP

#include <rawstor/location.h>
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

class Session final : public std::enable_shared_from_this<Session> {
private:
    struct Private {
        explicit Private() = default;
    };

    RawIOQueue* _queue;
    Server& _server;
    int _fd;
    RawIOEvent* _recv_event;
    ssize_t (Session::*_next)(const iovec*, unsigned int, size_t);
    RawstorOSTFrameHead _request_head;
    union {
        RawstorOSTFrameBasicBody basic;
        RawstorOSTFrameIOBody io;
    } _request_body;
    RawstorObject* _object;
    // Writes dispatched to rawstor_object_pwrite() whose completion hasn't
    // arrived yet -- see _recv_data()'s use of it to pause reading further
    // requests off the wire once too many pile up.
    unsigned int _writes_in_flight;

    // (Re-)arms the multishot recv, starting at a fresh request head. Used
    // both from the constructor and to resume reading after a pause (see
    // _recv_data()/_resume_recv_if_paused()).
    void _arm_recv();
    // Resumes the paused recv (see _recv_data()) once a completed write has
    // brought _writes_in_flight back under the cap. A no-op if recv isn't
    // currently paused, or is still over the cap.
    void _resume_recv_if_paused();
    static ssize_t _recv(
        const iovec* iov, unsigned int niov, size_t result, int error,
        void* data
    ) noexcept;
    ssize_t
    _recv(const iovec* iov, unsigned int niov, size_t result, int error);
    ssize_t _recv_head(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_body(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_data(const iovec* iov, unsigned int niov, size_t result);
    void _list(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _allocate(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _release(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _spec(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _info(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _set_object(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
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
    void _flush(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    std::vector<rawstd::URI> _targets(const RawstdUUID& uuid);

    // Tears the session down via Server::del_session() if the send itself
    // fails (e.g. a short write).
    void _send_response(
        const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
        uint64_t hash
    );
    void _send_response(
        const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
        uint64_t hash, const std::shared_ptr<std::vector<unsigned char>>& data
    );

public:
    static std::shared_ptr<Session>
    create(RawIOQueue* queue, Server& server, int fd);

    Session(Private, RawIOQueue* queue, Server& server, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    ~Session() noexcept;

    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SESSION_HPP
