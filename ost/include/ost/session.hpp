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
#include <string>
#include <unordered_set>
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

    /*
     * Completion context for an async object operation (allocate/release/
     * open). The session may be destroyed while the operation is in
     * flight, in which case the weak_ptr fails to lock and no response is
     * sent: _fd may already be closed or reused by another session.
     */
    struct OpCtx {
        std::weak_ptr<Session> session;
        RawstorOSTCommandType cmd;
        uint16_t cid;
    };

    /* Accumulator for the LIST_CHUNKS scan; see _list_chunks(). */
    struct ListCtx {
        std::weak_ptr<Session> session;
        uint16_t cid;
        std::vector<std::string> locations;
        size_t next;
        /* rawstor_object_list_async() output for the location in flight. */
        RawstorObjectListEntry* entries;
        size_t nentries;
        std::unordered_set<std::string> seen;
        std::vector<RawstorOSTFrameMetaBody> records;
    };

    /* Completion context for the async META query; see _meta(). */
    struct MetaCtx {
        std::weak_ptr<Session> session;
        uint16_t cid;
        uint8_t obj_id[16];
        RawstorObjectMeta meta;
    };

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

    /*
     * SET_OBJECT (the handshake) was received: it must be the first
     * command on every connection, anything else before it is a protocol
     * violation (the misconnection guard).
     */
    bool _handshaken;

    /* An object open is in flight; a concurrent SET_OBJECT gets EBUSY. */
    bool _open_pending;

    // Arms the multishot recv; only ever called once, from the
    // constructor.
    void _arm_recv();
    // Completions of the async object operations started by _allocate(),
    // _release() and _set_object(); each takes ownership of the OpCtx
    // passed as `data`.
    static int _op_complete(int result, void* data) noexcept;
    static int
    _open_complete(RawstorObject* object, int result, void* data) noexcept;
    static int _meta_complete(int result, void* data) noexcept;

    static void _list_next(std::unique_ptr<ListCtx> ctx);
    static void _list_send(std::unique_ptr<ListCtx> ctx);
    static int _list_complete(int result, void* data) noexcept;

    void _send_hello(uint16_t cid);

    static ssize_t _recv(
        const iovec* iov, unsigned int niov, size_t result, int error,
        void* data
    ) noexcept;
    ssize_t
    _recv(const iovec* iov, unsigned int niov, size_t result, int error);
    ssize_t _recv_head(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_body(const iovec* iov, unsigned int niov, size_t result);
    ssize_t _recv_data(const iovec* iov, unsigned int niov, size_t result);
    // Drains and discards the body of a request this server cannot serve,
    // so the stream stays framed after an -ENOSYS response.
    ssize_t _recv_ignore(const iovec* iov, unsigned int niov, size_t result);
    void _list(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _allocate(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameAllocateBody& body
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
        const RawstorOSTFrameHead& head,
        const RawstorOSTFrameSetObjectBody& body
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
    void _meta(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _set_state(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameMetaBody& body
    );
    /* CMD_LIST_CHUNKS: enumerate every object with its metadata. */
    void _list_chunks(const RawstorOSTFrameHead& head);
    void _flush(
        const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
    );
    void _unknown(const RawstorOSTFrameHead& head);

    /* Send a final response, then close the session once it is flushed. */
    void _close_after_response(const RawstorOSTFrameHead& head, int32_t res);

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
