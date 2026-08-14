#ifndef RAWSTOR_OSTBACKEND_SESSION_HPP
#define RAWSTOR_OSTBACKEND_SESSION_HPP

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <cstdint>
#include <deque>
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

    // A fully-received WRITE waiting for a free dispatch slot -- see
    // _write()/_dispatch_write()/_dispatch_next_pending_write().
    struct PendingWrite {
        RawstorOSTFrameHead head;
        uint64_t offset;
        bool sync;
        std::shared_ptr<std::vector<unsigned char>> data;
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
    // arrived yet -- see _write()'s use of it to queue rather than
    // dispatch once too many pile up.
    unsigned int _writes_in_flight;
    std::deque<PendingWrite> _pending_writes;
    // Sum of PendingWrite::data->size() across _pending_writes -- see
    // _write()'s use of it against Server::write_backlog_capacity() to reject
    // a write outright rather than let it grow _pending_writes without
    // bound.
    size_t _pending_writes_bytes;

    // Arms the multishot recv; only ever called once, from the
    // constructor.
    void _arm_recv();
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
    // Actually issues a validated WRITE to storage -- from _write()
    // directly if under write_throttle_limit(), or later from
    // _dispatch_next_pending_write() once a slot frees up.
    void _dispatch_write(
        const RawstorOSTFrameHead& head, uint64_t offset, bool sync,
        const std::shared_ptr<std::vector<unsigned char>>& data
    );
    // Called from a write's completion callback: dispatches the oldest
    // queued write, if any and if there's room for it now.
    void _dispatch_next_pending_write();
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

    // For ost/tests/ to verify write-throttling (see _recv_data()) without
    // depending on real storage-completion timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_in_flight;
    }

    // For ost/tests/ to verify the write backlog cap (see _write()).
    inline size_t pending_writes_bytes() const noexcept {
        return _pending_writes_bytes;
    }
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SESSION_HPP
