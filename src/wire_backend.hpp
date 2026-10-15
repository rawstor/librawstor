#ifndef RAWSTOR_WIRE_BACKEND_HPP
#define RAWSTOR_WIRE_BACKEND_HPP

#include <optional>

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
namespace wire {

class BackendOp;

// Shared TCP transport and member protocol for OST and MDS backends.
class Backend : public rawstor::Backend {
    friend class BackendOp;

private:
    uint16_t _cid_counter;

    rawio::Event* _read_event;
    std::unordered_map<uint16_t, std::shared_ptr<BackendOp>> _ops;

    // Running for as long as _recv_pump() is: begun by _connect() when it
    // launches the pump, ended by the pump itself on its way out. close()
    // settles on it after cancelling the pump's own recv registration --
    // that cancel only resolves once the cancel request itself is
    // processed, not once the pump has actually seen its registration's
    // final ECANCELED completion and returned, and a pump still suspended
    // on that when the queue goes away is never freed.
    rawstd::Gate _pump;
    rawstd::Gate _receive_resize;
    bool _large_receive_ring = false;

    void _start_receive_ring();
    rawstd::Task<void> _ensure_large_receive_ring();

protected:
    uint16_t _next_cid() noexcept { return _cid_counter++; }
    void _add_op(const std::shared_ptr<BackendOp>& op);

private:
    // The cid-dispatched counterpart of the old basic_request_async():
    // sends a RawstorFrameBasic-shaped request (remove/meta/info/
    // set_object/set_version/create_version all share this shape; LIST
    // has its own dedicated shape instead, see BackendOpList in the .cpp)
    // and awaits its response through the same _ops demultiplex mechanism
    // as every other op -- requires _recv_pump to already be running,
    // i.e. _connect() to have completed. `val`/`version_id` are never
    // both meaningful for the same command (protocol.h's own doc comment
    // on RawstorFrameBasicPayload); a caller that only needs one
    // leaves the other at its default (0/nil).
    template <typename T = char>
    rawstd::Task<std::vector<T>> _basic_request(
        RawstorCommandType cmd, const char* op_name, const RawstdUUID& id,
        uint64_t offset, uint64_t val = 0, const RawstdUUID& version_id = {}
    );
    // SYNC_PREPARE/SYNC_ACCEPT: sends `request` and returns the member's
    // reply.
    rawstd::Task<bool> _sync_request(
        const RawstorFrameSyncPropose& request, const char* op_name,
        RawstorObjectMeta& meta
    );
    void _fail_in_flight(int error);
    // Returns nullptr, rather than throwing, for an unregistered cid: a
    // response can legitimately race with Slot::_op() already having
    // failed and retried that same op on a different backend (e.g. after a
    // send-side error on this connection), in which case the cid was
    // already unregistered and the response is stale, not a corrupted
    // stream.
    BackendOp* _find_op(uint16_t cid);
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
    // _recv_pump()'s own way out on a stream it can no longer trust: fails
    // everything still in flight with `error`, if the backend is still
    // around.
    static void
    _recv_pump_failed(const std::weak_ptr<Backend>& weak, int error);

protected:
    // Native member requests and transport lifecycle shared by OST and MDS.
    rawstd::Task<void> _wire_connect();

    rawstd::Task<void> _wire_close();

    rawstd::Task<void> _wire_list_chunks(
        RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
        RawstdUUID& token, RawstdUUID version_id = {}
    );

    rawstd::Task<void> _wire_create(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstorObjectSpec& sp,
        RawstorMemberRole member_role
    );

    rawstd::Task<void> _wire_remove(
        const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t offset
    );

    rawstd::Task<void> _wire_remove_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    );

    rawstd::Task<std::vector<RawstdUUID>>
    _wire_list_versions(const RawstdUUID& id, uint64_t offset);

    rawstd::Task<std::vector<RawstorObjectMeta>> _wire_meta(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    );

    rawstd::Task<std::vector<rawstd::URI>> _wire_resolve_locations(
        const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id = {}
    );

    rawstd::Task<void> _wire_leave();

    rawstd::Task<bool> _wire_sync_prepare(
        const RawstdUUID& id, uint64_t offset,
        const RawstorObjectBallot& ballot, bool proposed,
        RawstorObjectMeta& meta
    );

    rawstd::Task<bool> _wire_sync_accept(
        const RawstdUUID& id, uint64_t offset, uint8_t member_index,
        const RawstorObjectBallot& ballot, const RawstorObjectBallot& next,
        const RawstorObjectConfig& config, bool proposed,
        RawstorObjectMeta& meta
    );

    rawstd::Task<void>
    _wire_set_object(const RawstdUUID& id, uint64_t offset, int flags);

    rawstd::Task<void> _wire_set_version(
        const RawstdUUID& object_id, uint64_t offset,
        const RawstdUUID& version_id
    );

    rawstd::Task<void> _wire_create_version(
        const RawstdUUID& idempotency_key, const RawstdUUID& id,
        uint64_t offset, const RawstdUUID& version_id
    );

public:
    // Encoded object commands use the same CID dispatcher as member requests.
    // max_size bounds the response body before allocation.
    rawstd::Task<std::vector<unsigned char>> exchange(
        const void* request, size_t size, RawstorCommandType cmd,
        size_t max_size
    );

    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);
    ~Backend();

    // The destination's Slot owns the copy state.
    rawstd::Task<void> set_state(
        const RawstdUUID& id, uint64_t offset,
        RawstorObjectSyncStateValue expected, RawstorObjectSyncStateValue state
    ) override final;

    rawstd::Task<void> set_config(
        const RawstdUUID& id, uint64_t offset, uint8_t member_index,
        const RawstorObjectConfig& config, unsigned int flags,
        std::optional<RawstorObjectSyncStateValue> state = std::nullopt
    ) override final;

    rawstd::Task<RawstorLocationInfo> info() override final;
};

} // namespace wire
} // namespace rawstor

#endif // RAWSTOR_WIRE_BACKEND_HPP
