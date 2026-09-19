#ifndef RAWSTOR_OST_BACKEND_HPP
#define RAWSTOR_OST_BACKEND_HPP

#include "backend.hpp"

#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/ringbuf.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <cstddef>

namespace rawstor {
namespace ost {

class BackendOp;

class Backend final : public rawstor::Backend {
    friend class BackendOp;

private:
    uint16_t _cid_counter;

    rawio::Event* _read_event;
    std::unordered_map<uint16_t, std::shared_ptr<BackendOp>> _ops;

    rawstd::Task<void> _connect() override;
    // The cid-dispatched counterpart of the old basic_request_async():
    // sends a RawstorOSTFrameBasic-shaped request (list/create/remove/
    // spec/info/set_object all share this shape) and awaits its response
    // through the same _ops demultiplex mechanism as every other op --
    // requires _recv_pump to already be running, i.e. _connect() to have
    // completed.
    template <typename T = char>
    rawstd::Task<std::vector<T>> _basic_request(
        RawstorOSTCommandType cmd, const char* op_name, const RawstdUUID& id,
        uint64_t chunk_offset, uint64_t val
    );
    // Same shape as _basic_request() above, for the handful of commands
    // that need a UUID snap_id instead of a plain uint64_t val
    // (RawstorOSTFrameSnapPayload, protocol.h): SET_OBJECT, SNAPSHOT,
    // SNAP_REMOVE.
    template <typename T = char>
    rawstd::Task<std::vector<T>> _snap_request(
        RawstorOSTCommandType cmd, const char* op_name, const RawstdUUID& id,
        uint64_t chunk_offset, const RawstdUUID& snap_id
    );
    void _fail_in_flight(int error);
    // Returns nullptr, rather than throwing, for an unregistered cid: a
    // response can legitimately race with Slot::_op() already having
    // failed and retried that same op on a different backend (e.g. after a
    // send-side error on this connection), in which case the cid was
    // already unregistered and the response is stale, not a corrupted
    // stream.
    BackendOp* _find_op(uint16_t cid);
    void _add_op(const std::shared_ptr<BackendOp>& op);
    void _remove_op(uint16_t cid);

    // Pulls the shared response stream forever, demultiplexing each
    // delivery by cid into whichever BackendOp is waiting for it -- the
    // coroutine-era replacement for set_object()'s old recv_multishot
    // callback. A free-standing detached loop keyed off a weak_ptr, not a
    // member coroutine capturing `this`/a strong shared_ptr, for the same
    // reason the old callback captured a weak_ptr: it must not keep this
    // Backend alive purely because its own recv registration exists (see
    // the .cpp for the full reentrant-teardown reasoning).
    static rawstd::DetachedTask _recv_pump(
        std::weak_ptr<Backend> weak, rawio::RecvStream stream,
        rawstd::TraceEvent trace_event
    );

public:
    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);
    ~Backend();

    rawstd::Task<void> close() override;

    rawstd::Task<void> list(
        unsigned int limit, std::vector<Target>& targets, ListedObject& token
    ) override;

    rawstd::Task<void> create(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstorObjectSpec& sp
    ) override;

    // `snap_id` nil for the live version, non-nil for a previously
    // snapshotted one -- relayed over the wire as one RAWSTOR_CMD_RELEASE
    // request either way (Backend::remove()'s own doc comment; protocol.h
    // widened this command's own payload for exactly this merge, same as
    // SET_OBJECT/OBJ_OPEN's own nil-means-live convention).
    rawstd::Task<void> remove(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) override;

    rawstd::Task<RawstorObjectSpec>
    spec(const RawstdUUID& id, uint64_t chunk_offset) override;

    rawstd::Task<RawstorObjectMeta>
    meta(const RawstdUUID& id, uint64_t chunk_offset) override;

    rawstd::Task<void> set_sync_state(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstorObjectSyncState& sync_state
    ) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    rawstd::Task<void> set_object(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) override;

    // Relays RAWSTOR_CMD_SNAPSHOT over the wire -- the remote rawstor-ost
    // forwards to its own local backend the same way (docs/mds.md,
    // "Snapshots").
    rawstd::Task<void> create_snapshot(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
    ) override;

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) override;

    rawstd::Task<size_t> discard(size_t size, off_t offset) override;

    rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync) override;

    rawstd::Task<void> flush() override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_BACKEND_HPP
