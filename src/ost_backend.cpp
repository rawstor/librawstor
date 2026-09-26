#include "ost_backend.hpp"

#include "opts.h"
#include "telemetry.hpp"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>
#include <rawio/stream.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <algorithm>
#include <exception>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
#include <utility>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256

namespace {

class BackendOp;

int validate_result(size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error("Unexpected event size: %zu != %zu\n", result, size);

    return EAGAIN;
}

// Slot::_with_retry() no longer distinguishes a well-formed
// rejection from the backend (response->body.res < 0) from a broken/
// malformed wire -- every failure here just reconnects and retries, up
// to the same rawstor_opts_io_attempts() budget, unless it's one
// is_permanent_backend_error() (see connection.cpp) already knows can
// never succeed on retry. EBADMSG is one such body.res value: the OST
// server sends it (see ost/src/client.cpp) only when the payload it just
// received doesn't hash to what the client declared, meaning the client
// and server have lost agreement on where in the byte stream the current
// frame even ends -- reconnecting is what recovers alignment on the next
// frame header, same as for a magic mismatch below.
int validate_response(const RawstorOSTFrameResponse* response) noexcept {
    assert(response != nullptr);

    if (response->head.magic != RAWSTOR_MAGIC) {
        rawstd_error(
            "Unexpected magic number: %x != %x\n", response->head.magic,
            RAWSTOR_MAGIC
        );
        return EPROTO;
    }

    if (response->body.res < 0) {
        int error = -response->body.res;
        rawstd_error("Server error: %s\n", strerror(error));
        return error;
    }

    return 0;
}

int validate_cmd(
    RawstorOSTCommandType cmd, RawstorOSTCommandType expected
) noexcept {
    if (cmd == expected) {
        return 0;
    }

    rawstd_error("Unexpected command: %d\n", cmd);
    return EPROTO;
}

int validate_hash(uint64_t hash, uint64_t expected) noexcept {
    if (hash == expected) {
        return 0;
    }

    rawstd_error(
        "Hash mismatch: %llx != %llx\n", (unsigned long long)hash,
        (unsigned long long)expected
    );
    return EPROTO;
}

// RawstorOSTFrameAllocatePayload::chunk_shift's own doc comment on why a
// shift, not the full value -- `chunk_size` is always a power of two
// (RawstorObjectSpec's own doc comment, target.h), 0 meaning no chunking.
uint8_t chunk_size_to_shift(uint64_t chunk_size) noexcept {
    return chunk_size == 0 ? 0
                           : static_cast<uint8_t>(__builtin_ctzll(chunk_size));
}

// chunk_shift comes straight off the wire, from a peer this end doesn't
// control -- 1ull << chunk_shift is undefined behavior once chunk_shift
// reaches 64, so that (and anything past it, since chunk_shift's own
// uint8_t range goes to 255) is rejected outright rather than silently
// misinterpreted.
uint64_t chunk_shift_to_size(uint8_t chunk_shift) {
    if (chunk_shift >= 64) {
        rawstd_error("Invalid chunk_shift: %u\n", chunk_shift);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    return chunk_shift == 0 ? 0 : (1ull << chunk_shift);
}

} // namespace

namespace {

uint64_t hash(const void* buf, size_t size) {
    return rawstd_hash_scalar(buf, size);
}

uint64_t hash(const iovec* iov, unsigned int niov) {
    uint64_t ret;
    int res = rawstd_hash_vector(iov, niov, &ret);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}

} // namespace

namespace rawstor {
namespace ost {

class BackendOp {
private:
    uint16_t _cid;
    bool _dispatched;

    // telemetry: request_cb() stamps _t_send_done once the request is
    // fully on the wire; _t_created (below, stamped at construction --
    // effectively the moment Slot::_op() dispatched this attempt)
    // to _t_send_done is slat, _t_send_done to the moment a response is
    // ready is rtt, and the co_await resolving is clat. 0 (never a real
    // timestamp, see telemetry::now()) marks "never sent", so _dispatch()
    // can tell a send that never completed apart from a real zero-length
    // gap.
    rawstor::telemetry::TimePoint _t_send_done;

    // Set by await_suspend() once whoever co_await's this op (always
    // exactly one caller, right after submitting the request) is known;
    // _dispatch() writes _result/_error and resumes it -- same split
    // value/error-then-resume shape as librawio's own Completion/
    // PollStream::Next.
    std::coroutine_handle<> _handle;
    size_t _result;
    int _error;

protected:
    rawstor::telemetry::TimePoint _t_created;
    // A string literal (e.g. "pread"/"pwrite"/"flush"), not owned; size
    // and offset are 0 for ops without either (flush). Set once at
    // construction by each subclass, purely for _dispatch()'s
    // telemetry::record_op() call.
    const char* _op_name;
    size_t _op_size;
    off_t _op_offset;

    rawstd::TraceEvent _trace_event;
    // A strong reference, not just a back-pointer: a BackendOp can outlive
    // Backend::_ops's own copy of it (e.g. a still-pending send/sendmsg
    // completion keeps a BackendOp alive independently, via its own
    // captured shared_ptr, even after the owning Backend is gone from
    // Slot::_backends and its _ops member has been destroyed). This
    // keeps the Backend itself alive for as long as any BackendOp -- in
    // _ops or floating in a pending completion closure -- still needs it.
    std::shared_ptr<rawstor::ost::Backend> _backend;
    RawstorOSTFrameResponse _response;

    inline void _dispatch(size_t result, int error) {
        if (_dispatched) {
            // Already delivered -- e.g. Backend::_fail_in_flight() forced
            // this op's completion while its own request send was still
            // pending, and that send has now independently completed (with
            // its own success or error). The caller has already been
            // notified once; do not notify it again, and do not touch
            // _backend (already removed from its _ops, possibly gone).
            return;
        }
        _dispatched = true;
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight end");

        // rtt/clat only mean something for a request that actually made
        // it onto the wire and got a real response back -- a failed
        // send, a stray cid, or a torn-down backend all reach here with
        // an error and nothing useful to measure.
        bool timed = !error && _t_send_done != 0;
        rawstor::telemetry::TimePoint t_response_ready = 0;
        rawstor::telemetry::TimePoint slat = 0;
        rawstor::telemetry::TimePoint rtt = 0;
        if (timed) {
            t_response_ready = rawstor::telemetry::now();
            slat = _t_send_done - _t_created;
            rtt = t_response_ready - _t_send_done;
            rawstor::telemetry::record_rtt(rtt);
        }

        _result = result;
        _error = error;
        _backend->_remove_op(_cid);

        // clat/lat and the top-10 sample are only meaningful alongside
        // rtt, so this shares the same `timed` gate.
        if (timed) {
            rawstor::telemetry::TimePoint t_now = rawstor::telemetry::now();
            rawstor::telemetry::TimePoint clat = t_now - t_response_ready;
            rawstor::telemetry::record_clat(clat);
            rawstor::telemetry::record_op(
                t_now - _t_created, slat, rtt, clat, _op_name, _op_size,
                _op_offset
            );
        }

        if (_handle) {
            _handle.resume();
        }
    }

public:
    BackendOp(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const rawstd::TraceEvent& trace_event, const char* op_name,
        size_t op_size, off_t op_offset
    ) :
        _cid(cid),
        _dispatched(false),
        _t_send_done(0),
        _handle(),
        _result(0),
        _error(0),
        _t_created(rawstor::telemetry::now()),
        _op_name(op_name),
        _op_size(op_size),
        _op_offset(op_offset),
        _trace_event(trace_event),
        _backend(backend) {}

    BackendOp(const BackendOp&) = delete;
    BackendOp(BackendOp&&) = delete;
    virtual ~BackendOp() = default;

    BackendOp& operator=(const BackendOp&) = delete;
    BackendOp& operator=(BackendOp&&) = delete;

    inline uint16_t cid() const noexcept { return _cid; }

    virtual size_t request_size() const noexcept = 0;

    void request_cb(int error) {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight begin");

        if (!error) {
            _t_send_done = rawstor::telemetry::now();
            rawstor::telemetry::record_slat(_t_send_done - _t_created);
        } else {
            _dispatch(0, error);
        }
    }

    // Returns the body size that follows this response -- 0 means none.
    virtual size_t
    response_head_cb(const RawstorOSTFrameResponse* response, int error) = 0;

    virtual void response_body_cb(const iovec*, unsigned int, size_t) {}

    // Awaiter protocol: co_await *op right after submitting the request.
    // await_ready() covers the case where _dispatch() already fired
    // synchronously (an immediate send failure via request_cb()) before
    // the co_await is even reached.
    bool await_ready() const noexcept { return _dispatched; }
    void await_suspend(std::coroutine_handle<> h) noexcept { _handle = h; }
    size_t await_resume() {
        if (_error) {
            RAWSTD_THROW_SYSTEM_ERROR(_error);
        }
        return _result;
    }
};

class BackendOpRead final : public BackendOp {
private:
    void* _buf;
    size_t _size;
    RawstorOSTFrameIO _request;

    uint64_t _hash;

public:
    BackendOpRead(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        void* buf, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "pread", size, offset),
        _buf(buf),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .payload =
                {
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)_size,
                    .hash = 0,
                    .flags = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_READ);
        }

        if (!error && response->body.res > 0) {
            // Trust the server's own reported byte count for how much
            // body follows, not our own originally-requested _size.
            _hash = response->body.hash;
            return static_cast<size_t>(response->body.res);
        }

        // No body follows either way: a real error, or a genuine
        // zero-byte read (response->body.res == 0, nothing to send).
        _dispatch(0, error);
        return 0;
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result
    ) override {
        int error = validate_hash(hash(iov, niov), _hash);
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (result) {
            rawstd_iovec_to_buf(iov, niov, 0, _buf, result);
        }

        _dispatch(result, error);
    }
};

class BackendOpReadV final : public BackendOp {
private:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;
    RawstorOSTFrameIO _request;

    uint64_t _hash;

public:
    BackendOpReadV(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "preadv", size, offset),
        _iov(iov),
        _niov(niov),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .payload =
                {
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)_size,
                    .hash = 0,
                    .flags = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_READ);
        }

        if (!error && response->body.res > 0) {
            // Trust the server's own reported byte count for how much
            // body follows, not our own originally-requested _size.
            _hash = response->body.hash;
            return static_cast<size_t>(response->body.res);
        }

        // No body follows either way: a real error, or a genuine
        // zero-byte read (response->body.res == 0, nothing to send).
        _dispatch(0, error);
        return 0;
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result
    ) override {
        int error = validate_hash(hash(iov, niov), _hash);
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (result) {
            rawstd_iovec_to_iovec(iov, niov, 0, _iov, _niov);
        }

        _dispatch(result, error);
    }
};

class BackendOpWrite final : public BackendOp {
private:
    std::vector<iovec> _iov;
    RawstorOSTFrameIO _request;
    msghdr _msg;

public:
    BackendOpWrite(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const void* buf, size_t size, off_t offset, bool sync,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "pwrite", size, offset),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .payload = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash(buf, size),
                .flags = static_cast<uint8_t>(sync ? RAWSTOR_FLAG_SYNC : 0),
            },
        }) {
        _iov.reserve(2);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        _iov.push_back({
            .iov_base = const_cast<void*>(buf),
            .iov_len = size,
        });
        _msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov.data(),
            .msg_iovlen = static_cast<decltype(_msg.msg_iovlen)>(_iov.size()),
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    }

    const msghdr* request_msg() const noexcept { return &_msg; }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.payload.len;
    }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        // A write response never carries a body, regardless of error.
        return 0;
    }
};

class BackendOpWriteV final : public BackendOp {
private:
    RawstorOSTFrameIO _request;
    std::vector<iovec> _iov;
    msghdr _msg;

public:
    BackendOpWriteV(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync, const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "pwritev", size, offset),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .payload = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash(iov, niov),
                .flags = static_cast<uint8_t>(sync ? RAWSTOR_FLAG_SYNC : 0),
            },
        }) {
        _iov.reserve(1 + niov);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        for (unsigned int i = 0; i < niov; ++i) {
            _iov.push_back(iov[i]);
        }
        _msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov.data(),
            .msg_iovlen = static_cast<decltype(_msg.msg_iovlen)>(_iov.size()),
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    }

    const msghdr* request_msg() const noexcept { return &_msg; }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.payload.len;
    }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        // A write response never carries a body, regardless of error.
        return 0;
    }
};

// Shared by BackendOpDiscard/BackendOpWriteZeroes below: both carry an
// offset+len request (RawstorOSTFrameIO, same shape as BackendOpRead's,
// minus any payload) and a response that never carries a body -- same
// terminal shape as BackendOpWrite's own response_head_cb().
class BackendOpNoPayloadIO : public BackendOp {
protected:
    RawstorOSTCommandType _cmd;
    RawstorOSTFrameIO _request;

public:
    BackendOpNoPayloadIO(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        RawstorOSTCommandType cmd, const char* op_name, size_t size,
        off_t offset, uint8_t flags, const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, op_name, size, offset),
        _cmd(cmd),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = cmd,
                    .cid = cid,
                },
            .payload = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = 0,
                .flags = flags,
            },
        }) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, _cmd);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        // Neither a discard nor a write-zeroes response ever carries a
        // body, regardless of error.
        return 0;
    }
};

class BackendOpDiscard final : public BackendOpNoPayloadIO {
public:
    BackendOpDiscard(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        size_t size, off_t offset, const rawstd::TraceEvent& trace_event
    ) :
        BackendOpNoPayloadIO(
            backend, cid, RAWSTOR_CMD_DISCARD, "discard", size, offset, 0,
            trace_event
        ) {}
};

class BackendOpWriteZeroes final : public BackendOpNoPayloadIO {
public:
    BackendOpWriteZeroes(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        size_t size, off_t offset, bool unmap, bool sync,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOpNoPayloadIO(
            backend, cid, RAWSTOR_CMD_WRITE_ZEROES, "write_zeroes", size,
            offset,
            (unmap ? RAWSTOR_FLAG_UNMAP : 0) | (sync ? RAWSTOR_FLAG_SYNC : 0),
            trace_event
        ) {}
};

class BackendOpFlush final : public BackendOp {
private:
    RawstorOSTFrameBasic _request;

public:
    BackendOpFlush(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "flush", 0, 0),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_FLUSH,
                    .cid = cid,
                },
            .payload = {
                .object_id = {},
                .offset = 0,
                .snapshot_id = {},
                .val = 0,
            },
        }) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_FLUSH);
        }

        _dispatch(0, error);

        // A flush response never carries a body, regardless of error.
        return 0;
    }
};

// SET_SYNC_STATE's request carries the full RawstorOSTFrameMetaPayload (not
// just object_id/offset/val like BackendOpBasic below), so it needs its own
// request shape -- the response is otherwise the same no-payload
// acknowledgement as BackendOpFlush above.
class BackendOpSetState final : public BackendOp {
private:
    RawstorOSTFrameSyncState _request;

public:
    BackendOpSetState(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstorObjectSyncState& sync_state,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "set_sync_state", 0, 0),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SET_SYNC_STATE,
                    .cid = cid,
                },
            .payload = {
                .object_id = {},
                .chunk_offset = chunk_offset,
                .epoch = sync_state.epoch,
                .sync_id = sync_state.sync_id,
                .sync_id_history = {},
                .state = static_cast<RawstorOSTSyncStateType>(sync_state.state),
            },
        }) {
        memcpy(
            _request.payload.object_id, id.bytes,
            sizeof(_request.payload.object_id)
        );
        memcpy(
            _request.payload.sync_id_history, sync_state.sync_id_history,
            sizeof(_request.payload.sync_id_history)
        );
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error =
                validate_cmd(response->head.cmd, RAWSTOR_CMD_SET_SYNC_STATE);
        }

        _dispatch(0, error);

        // A set_sync_state response never carries a body, regardless of
        // error.
        return 0;
    }
};

// ALLOCATE's request carries the object's own size and its caller's
// mirrors intent as a RawstorOSTFrameAllocatePayload (not just object_id/
// offset/val like BackendOpBasic below), so it needs its own request shape
// -- the response is otherwise the same no-payload acknowledgement as
// BackendOpFlush above.
class BackendOpAllocate final : public BackendOp {
private:
    RawstorOSTFrameAllocate _request;

public:
    BackendOpAllocate(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstorObjectSpec& sp, const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "create", 0, 0),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_ALLOCATE,
                    .cid = cid,
                },
            .payload = {
                .object_id = {},
                .chunk_offset = chunk_offset,
                .size = sp.size,
                .chunk_shift = chunk_size_to_shift(sp.chunk_size),
                .stripe_width = sp.stripe_width,
                .failure_domain = sp.failure_domain,
                .member_kind = (uint8_t)sp.member_kind,
                .width = (uint8_t)sp.width,
                .reserved1 = 0,
                .reserved2 = 0,
            },
        }) {
        memcpy(
            _request.payload.object_id, id.bytes,
            sizeof(_request.payload.object_id)
        );
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_ALLOCATE);
        }

        _dispatch(0, error);

        // A create response never carries a body, regardless of error.
        return 0;
    }
};

// The cid-dispatched counterpart of BackendOpRead/BackendOpWrite/
// BackendOpFlush above, for the RawstorOSTFrameBasic-shaped commands
// (remove/meta/info/set_object/set_snapshot/create_snapshot) -- these
// carry no hash and have either no response body or a body of some
// number of T's, per response.body.res. Routed through the same
// _recv_pump demultiplex mechanism as every other op, now that the pump
// starts in Backend::_connect() instead of after the first request
// round-trips. `val`/`snapshot_id` are never both meaningful for the
// same command (protocol.h's own doc comment on
// RawstorOSTFrameBasicPayload) but both live in this one op regardless,
// so every such command shares one request path rather than two nearly
// identical ones.
template <typename T = char>
class BackendOpBasic final : public BackendOp {
private:
    RawstorOSTCommandType _cmd;
    RawstorOSTFrameBasic _request;
    std::vector<T> _response_data;

public:
    BackendOpBasic(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        RawstorOSTCommandType cmd, const char* op_name, const RawstdUUID& id,
        uint64_t offset, uint64_t val, const RawstdUUID& snapshot_id,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, op_name, 0, 0),
        _cmd(cmd),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = cmd,
                    .cid = cid,
                },
            .payload = {
                .object_id = {},
                .offset = offset,
                .snapshot_id = {},
                .val = val,
            },
        }) {
        memcpy(
            _request.payload.object_id, id.bytes,
            sizeof(_request.payload.object_id)
        );
        memcpy(
            _request.payload.snapshot_id, snapshot_id.bytes,
            sizeof(_request.payload.snapshot_id)
        );
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, _cmd);
        }

        if (!error && response->body.res > 0) {
            // A malformed body size means we can no longer trust where
            // the next frame starts either -- letting this throw (per
            // response_head_cb()'s documented contract) fails every op
            // still in flight on this backend instead of silently
            // desyncing the stream.
            if (response->body.res % sizeof(T) != 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
            return static_cast<size_t>(response->body.res);
        }

        _dispatch(0, error);
        return 0;
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result
    ) override {
        _response_data.resize(result / sizeof(T));
        rawstd_iovec_to_buf(iov, niov, 0, _response_data.data(), result);
        _dispatch(result, 0);
    }

    std::vector<T> take_response_data() { return std::move(_response_data); }
};

// LIST's own request/response shape (RawstorOSTFrameList/
// RawstorOSTFrameListEntry, protocol.h's own doc comment on why it isn't
// just another BackendOpBasic<T>) -- otherwise the same terminal shape as
// BackendOpBasic<RawstorOSTFrameListEntry> would have been.
class BackendOpList final : public BackendOp {
private:
    RawstorOSTFrameList _request;
    std::vector<RawstorOSTFrameListEntry> _response_data;

public:
    BackendOpList(
        const std::shared_ptr<rawstor::ost::Backend>& backend, uint16_t cid,
        const ChunkCursor& token, unsigned int limit,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "list", 0, 0),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_LIST,
                    .cid = cid,
                },
            .payload = {
                .token_id = {},
                .token_chunk_offset = token.offset,
                .token_snapshot_id = {},
                .limit = limit,
            },
        }) {
        memcpy(
            _request.payload.token_id, token.id.bytes,
            sizeof(_request.payload.token_id)
        );
        // token_snapshot_id stays all-zero (the aggregate init above):
        // list_chunks() never returns a snapshot, so its own cursor never
        // needs to resume mid one either.
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t response_head_cb(
        const RawstorOSTFrameResponse* response, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_LIST);
        }

        if (!error && response->body.res > 0) {
            if (response->body.res % sizeof(RawstorOSTFrameListEntry) != 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
            return static_cast<size_t>(response->body.res);
        }

        _dispatch(0, error);
        return 0;
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result
    ) override {
        _response_data.resize(result / sizeof(RawstorOSTFrameListEntry));
        rawstd_iovec_to_buf(iov, niov, 0, _response_data.data(), result);
        _dispatch(result, 0);
    }

    std::vector<RawstorOSTFrameListEntry> take_response_data() {
        return std::move(_response_data);
    }
};

void Backend::_fail_in_flight(int error) {
    if (_ops.empty()) {
        return;
    }

    // Every op still in _ops needs this, not just the ones whose
    // request has already finished sending: an op between _add_op() and
    // its own request_cb() firing is just as stranded by this backend
    // going away, and its pending send is not guaranteed to itself
    // complete with an error (e.g. if the socket is never explicitly
    // closed/cancelled once this backend is replaced) -- skipping it
    // here left it waiting forever. BackendOp guards against the
    // resulting double dispatch if that pending send does independently
    // complete afterwards.
    std::vector<std::shared_ptr<BackendOp>> ops;
    ops.reserve(_ops.size());
    for (const auto& i : _ops) {
        ops.push_back(i.second);
    }

    // response_head_cb()'s return value only matters to a caller steering
    // the *next* read off a live response -- irrelevant here, every op is
    // being force-failed, not fed a real response.
    for (const auto& i : ops) {
        i->response_head_cb(nullptr, error);
    }
}

BackendOp* Backend::_find_op(uint16_t cid) {
    auto it = _ops.find(cid);
    if (it == _ops.end()) {
        return nullptr;
    }

    return it->second.get();
}

void Backend::_add_op(const std::shared_ptr<BackendOp>& op) {
    if (_read_event == nullptr) {
        // _recv_pump has already exited (e.g. the connection died right
        // after a previous op's response, before this one was ever
        // issued -- _connect() itself and this op's own caller can both
        // legitimately run to completion in between, with nothing to
        // co_await in the meantime that would surface that death
        // earlier). Nobody will ever demultiplex a response for this op,
        // so fail it immediately instead of registering it into _ops,
        // where it would sit forever unanswered. The caller still goes
        // on to attempt its own send -- wasted but harmless, since
        // response_head_cb() below has already resolved this op and
        // request_cb()'s own _dispatch() call is a no-op past that
        // point.
        //
        // response_head_cb() below still runs this op through
        // BackendOp::_dispatch(), which unconditionally calls
        // _remove_op() -> telemetry::op_finished() -- so this op needs a
        // matching op_started() here despite never reaching _ops, or
        // in-flight goes negative for every op forced through this path.
        rawstor::telemetry::op_started();
        op->response_head_cb(nullptr, ECONNRESET);
        return;
    }
    _ops[op->cid()] = op;
    rawstor::telemetry::op_started();
}

void Backend::_remove_op(uint16_t cid) {
    _ops.erase(cid);
    rawstor::telemetry::op_finished();
}

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Backend(p, queue, location),
    _cid_counter(0),
    _read_event(nullptr) {
}

Backend::~Backend() {
    if (_read_event != nullptr) {
        try {
            _queue.cancel(_read_event);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel event: %s\n", e.what());
        }
        _read_event = nullptr;
    }
}

rawstd::Task<void> Backend::_connect() {
    // Every failure below -- including a malformed location, which can't
    // be fixed by retrying but is otherwise indistinguishable here from a
    // transient one -- means "couldn't establish this backend"; all of
    // them surface as a plain std::system_error, which
    // Slot::_with_retry() reacts to by reconnecting and retrying
    // (see connection.cpp).
    if (!location().path().str().empty() && location().path().str() != "/") {
        rawstd_error("Empty path expected: %s\n", location().str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    int res;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    std::exception_ptr connect_error;
    try {
        // Also puts fd in non-blocking mode, which the async connect()
        // below relies on (the poll backend needs a non-blocking
        // ::connect() to return EINPROGRESS instead of blocking inline).
        rawio::Queue::setup_fd(fd);

        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            res = rawstd_socket_set_snd_timeout(fd, so_sndtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            res = rawstd_socket_set_rcv_timeout(fd, so_rcvtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
        if (tcp_user_timeo != 0) {
            res = rawstd_socket_set_user_timeout(fd, tcp_user_timeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        sockaddr_in servaddr = {};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(location().port());

        res = inet_pton(
            AF_INET, location().hostname().c_str(), &servaddr.sin_addr
        );
        if (res == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        co_await _queue.connect(fd, (sockaddr*)&servaddr, sizeof(servaddr));
    } catch (...) {
        // co_await is not permitted inside a catch handler -- stash the
        // exception and rethrow it once out of the handler, below, after
        // the cleanup co_await.
        connect_error = std::current_exception();
    }

    if (connect_error) {
        // Best-effort: close() failing here must not replace
        // connect_error with one of its own.
        try {
            co_await _queue.close(fd);
        } catch (...) {
        }
        rawstd_debug("fd %d: Closed\n", fd);
        std::rethrow_exception(connect_error);
    }

    set_fd(fd);

    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('m', "%s\n", "multishot recv");
    // 64 * 16 buffers of 1u<<17 (128KiB) each = 128MiB: comfortably covers
    // rawstor-vhost's usual worst case (its default write-throttle-limit
    // of 128 concurrent requests, each up to a virtio-blk transfer's
    // realistic ~512KiB) with headroom, so a healthy client pipelining
    // that many in-flight requests doesn't overflow this ring and force a
    // reconnect (see ost/src/client.cpp's matching registration for the
    // request-reading side of the same problem).
    rawio::RecvStream stream = _queue.recv_multishot(
        fd, 1u << 17, 64 * 16, sizeof(RawstorOSTFrameResponse), 0
    );
    _read_event = stream.event();
    _recv_pump(
        std::static_pointer_cast<Backend>(shared_from_this()),
        std::move(stream), trace_event
    );
    // _recv_pump() may have stored a pending exception instead of
    // throwing it directly -- see rawstd::DetachedTask's own doc comment
    // for why, and why this is the one call site that needs to check.
    rawstd::DetachedTask::rethrow_if_pending();
}

rawstd::Task<void> Backend::close() {
    // Anything still in _ops at this point was never told this backend
    // is going away otherwise. _recv_pump()'s own catch block below only
    // reaches _fail_in_flight() for a genuine framing/transport error it
    // detected itself; the _queue.cancel() a couple lines down resumes
    // that same pump with ECANCELED instead, which it treats as "nothing
    // left to clean up" and returns without touching _ops -- true when
    // close() is called once every op has already finished, but not when
    // a *sibling* op's own failure is what triggered this close() (e.g.
    // via Slot::invalidate_backend(), reacting to any
    // std::system_error one op's own Slot::_with_retry() caught --
    // a dropped connection, but just as easily a well-formed error
    // response for one op on an otherwise perfectly healthy connection,
    // which _recv_pump has no way to notice on its own since nothing
    // about the wire ever looked wrong): this backend's other, already-
    // sent ops are still sitting in _ops purely waiting on a response
    // that will now never come. Fail them now instead of leaving their
    // coroutines suspended forever; a no-op if _ops is already empty
    // (the common case).
    _fail_in_flight(ECONNABORTED);

    if (_read_event != nullptr) {
        co_await _queue.cancel(_read_event);
        _read_event = nullptr;
    }

    int f = fd();
    if (f != -1) {
        set_fd(-1);
        // _fail_in_flight() above only pre-resolves each op's eventual
        // `co_await *op` (the response half) -- it does nothing for an
        // op whose coroutine hasn't reached that yet because it's still
        // suspended earlier, in its own co_await _queue.sendmsg()/send()
        // (registered into _ops via _add_op(), but its request hasn't
        // finished sending). Queue::close() below is a plain
        // IORING_OP_CLOSE with no cancel-first step of its own (unlike
        // ~Queue()'s io_uring_register_sync_cancel() sweep at shutdown),
        // so without this, that still-pending send's own completion can
        // go undelivered forever once the fd is closed out from under
        // it -- its coroutine left suspended with nothing left to ever
        // resume it. Cancel everything else still outstanding on this fd
        // first; a no-op (ENOENT) in the common case where there's
        // nothing left in flight by now.
        co_await _queue.cancel(f);
        co_await _queue.close(f);
    }
}

template <typename T>
rawstd::Task<std::vector<T>> Backend::_basic_request(
    RawstorOSTCommandType cmd, const char* op_name, const RawstdUUID& id,
    uint64_t offset, uint64_t val, const RawstdUUID& snapshot_id
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('s', "%s\n", op_name);

    std::shared_ptr<BackendOpBasic<T>> op = std::make_shared<BackendOpBasic<T>>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        cmd, op_name, id, offset, val, snapshot_id, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_await *op;
    co_return op->take_response_data();
}

rawstd::Task<void> Backend::list_chunks(
    unsigned int limit, std::vector<std::pair<RawstdUUID, uint64_t>>& chunks,
    ChunkCursor& token
) {
    ChunkCursor input_token = token;
    chunks.clear();
    token = {};

    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('l', "fd = %d\n", fd());

    std::shared_ptr<BackendOpList> op = std::make_shared<BackendOpList>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        input_token, limit, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    std::vector<RawstorOSTFrameListEntry> entries;
    try {
        co_await *op;
        entries = op->take_response_data();
    } catch (const std::system_error&) {
        throw;
    } catch (...) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    // The remote rawstor-ost's own response always carries one more entry
    // than the real page: the resume cursor it reports, last (mirroring
    // rawstor::Location::list()'s own doc comment on why -- the far end
    // may itself be relaying across more than one local location, whose
    // own merged resume point isn't necessarily identical to the last
    // real entry returned). An empty response (nothing at all, not even
    // a cursor entry) means the far end is already exhausted.
    if (entries.empty()) {
        co_return;
    }

    chunks.reserve(entries.size() - 1);
    for (size_t i = 0; i + 1 < entries.size(); ++i) {
        const RawstorOSTFrameListEntry& entry = entries[i];
        RawstdUUID id;
        memcpy(id.bytes, entry.id, sizeof(id.bytes));
        chunks.emplace_back(id, entry.chunk_offset);
    }

    const RawstorOSTFrameListEntry& token_entry = entries.back();
    memcpy(token.id.bytes, token_entry.id, sizeof(token.id.bytes));
    token.offset = token_entry.chunk_offset;
}

// sp is forwarded on the wire unchanged (see BackendOpAllocate); the
// remote rawstor-ost's own Client::_allocate() derives its own local
// copy count from its own configured location count directly (see its
// own comment), never from anything in the request -- this connection is
// still one copy from its caller's point of view, same as every other
// backend.
rawstd::Task<void> Backend::create(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('c', "fd = %d\n", fd());

    std::shared_ptr<BackendOpAllocate> op = std::make_shared<BackendOpAllocate>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        id, offset, sp, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_await *op;
}

rawstd::Task<void> Backend::remove(const RawstdUUID& id, uint64_t offset) {
    try {
        co_await _basic_request(RAWSTOR_CMD_RELEASE, "remove", id, offset);
    } catch (const std::system_error&) {
        throw;
    } catch (...) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    co_return;
}

rawstd::Task<void> Backend::remove_snapshot(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& snapshot_id
) {
    try {
        co_await _basic_request(
            RAWSTOR_CMD_RELEASE, "remove_snapshot", id, offset, 0, snapshot_id
        );
    } catch (const std::system_error&) {
        throw;
    } catch (...) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    co_return;
}

rawstd::Task<void> Backend::create_snapshot(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& snapshot_id
) {
    try {
        co_await _basic_request(
            RAWSTOR_CMD_SNAPSHOT, "create_snapshot", id, offset, 0, snapshot_id
        );
    } catch (const std::system_error&) {
        throw;
    } catch (...) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    co_return;
}

rawstd::Task<RawstorObjectMeta>
Backend::meta(const RawstdUUID& id, uint64_t offset) {
    rawstd_info("%s: Reading object metadata...\n", str().c_str());

    RawstorObjectMeta ret = {};
    try {
        std::vector<char> response =
            co_await _basic_request(RAWSTOR_CMD_META, "meta", id, offset, 0);
        if (response.size() != sizeof(RawstorOSTFrameMetaPayload)) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        const RawstorOSTFrameMetaPayload& payload =
            *static_cast<const RawstorOSTFrameMetaPayload*>(
                static_cast<const void*>(response.data())
            );
        ret.spec.size = payload.size;
        ret.spec.member_kind =
            static_cast<RawstorMemberKind>(payload.member_kind);
        // payload.width is the chunk's own persisted redundancy width
        // (docs/mds.md, chunk_meta) -- 0 for a plain object that was never
        // given one (Target::meta()'s own doc comment on the resulting
        // fallback).
        ret.spec.width = payload.width;
        ret.spec.chunk_size = chunk_shift_to_size(payload.chunk_shift);
        ret.sync_state.epoch = payload.epoch;
        ret.sync_state.sync_id = payload.sync_id;
        memcpy(
            ret.sync_state.sync_id_history, payload.sync_id_history,
            sizeof(ret.sync_state.sync_id_history)
        );
        ret.sync_state.state =
            static_cast<RawstorObjectSyncStateValue>(payload.state);
    } catch (const std::system_error&) {
        throw;
    } catch (...) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    rawstd_info("%s: Object metadata successfully received\n", str().c_str());

    co_return ret;
}

rawstd::Task<void> Backend::set_sync_state(
    const RawstdUUID& id, uint64_t offset,
    const RawstorObjectSyncState& sync_state
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('s', "fd = %d\n", fd());

    std::shared_ptr<BackendOpSetState> op = std::make_shared<BackendOpSetState>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        id, offset, sync_state, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_await *op;
}

rawstd::Task<RawstorLocationInfo> Backend::info() {
    rawstd_info("%s: Reading location info...\n", str().c_str());

    RawstorLocationInfo ret = {};
    try {
        RawstdUUID unused_id = {};
        std::vector<char> response = co_await _basic_request(
            RAWSTOR_CMD_LOCATION_INFO, "info", unused_id, 0, 0
        );
        if (response.size() != sizeof(ret)) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        ret = *static_cast<RawstorLocationInfo*>(
            static_cast<void*>(response.data())
        );
    } catch (const std::system_error&) {
        throw;
    } catch (...) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    rawstd_info("%s: Location info successfully received\n", str().c_str());

    co_return ret;
}

rawstd::Task<void>
Backend::set_object(const RawstdUUID& id, uint64_t offset, int flags) {
    // The demultiplex pump is already running by now -- _connect() starts it
    // before this is ever reachable -- so this is just another
    // cid-dispatched request like list()/create()/....
    assert(_read_event != nullptr);

    // `flags` rides `val` (protocol.h's own doc comment on SET_OBJECT).
    co_await _basic_request(
        RAWSTOR_CMD_SET_OBJECT, "set_object", id, offset,
        static_cast<uint64_t>(flags)
    );
}

rawstd::Task<void> Backend::set_snapshot(
    const RawstdUUID& object_id, uint64_t offset, const RawstdUUID& snapshot_id
) {
    assert(_read_event != nullptr);

    // A snapshot is only ever opened read-only (Target::open()'s own
    // check), which is exactly what the remote rawstor-ost's own
    // rawstor_target_open() requires of a bound-snapshot target.
    co_await _basic_request(
        RAWSTOR_CMD_SET_OBJECT, "set_snapshot", object_id, offset,
        RAWSTOR_READONLY, snapshot_id
    );
}

// See ost_backend.hpp's doc comment on why `weak`, not a strong
// shared_ptr/`this`-capturing member coroutine.
rawstd::DetachedTask Backend::_recv_pump(
    std::weak_ptr<Backend> weak, rawio::RecvStream stream,
    rawstd::TraceEvent trace_event
) {
    try {
        while (true) {
            // --- read and parse this message's frame head ---
            RawstorOSTFrameResponse response;
            rawio::RecvStream::Item head_item =
                co_await stream.next(sizeof(response));

            std::shared_ptr<Backend> backend = weak.lock();
            if (backend == nullptr) {
                co_return;
            }

            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu\n", head_item.size(), sizeof(response)
            );

            int error = validate_result(sizeof(response), head_item.size());
            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }

            // rawstd_iovec_to_buf() is plain C -- it cannot throw -- and
            // validate_result() above already confirmed head_item holds
            // exactly sizeof(response) bytes, so this always copies the
            // response in full.
            rawstd_iovec_to_buf(
                head_item.iov(), head_item.niov(), 0, &response,
                sizeof(response)
            );
            uint16_t cid = response.head.cid;

            BackendOp* op = backend->_find_op(cid);
            if (op == nullptr) {
                // A stray/late response for an op this connection
                // already failed and that Slot::_op() has since
                // retried on a different backend. We have no op to ask
                // whether this response carries a body, so we can no
                // longer trust where the next message starts either --
                // treat it exactly like a real framing error, not
                // something to recover from.
                rawstd_error("Unexpected cid: %u\n", cid);
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }

            // op->response_head_cb() synchronously resumes whatever is
            // co_await-ing that op (Slot::_op()'s retry chain,
            // eventually a detached C-ABI adapter rethrowing after its
            // callback signalled failure) -- but resuming a
            // rawstd::Task<T> never lets an exception escape back into
            // its resumer (Task<T>::unhandled_exception() stores it for
            // later, it doesn't rethrow), so nothing from *that* should
            // reach here in practice. What can still throw is
            // response_head_cb() itself (e.g. std::bad_alloc); once that
            // happens we can no longer trust that body_size was ever
            // determined, so we can't safely know where the next head
            // starts either -- the catch clauses below treat it exactly
            // like a framing error either way.
            size_t body_size = op->response_head_cb(&response, 0);
            if (body_size == 0) {
                continue;
            }

            // --- this response carries a body: read it too, before
            // moving on to the next message's head ---
            rawio::RecvStream::Item body_item = co_await stream.next(body_size);

            backend = weak.lock();
            if (backend == nullptr) {
                co_return;
            }

            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu\n", body_item.size(), body_size
            );

            error = validate_result(body_size, body_item.size());
            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }

            // Re-derive op instead of trusting the pointer found above
            // across this co_await: it may have been failed and removed
            // from _ops (e.g. by an unrelated "unexpected cid" desync)
            // while this body read was in flight.
            op = backend->_find_op(cid);
            if (op == nullptr) {
                rawstd_error("Unexpected cid: %u\n", cid);
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }

            // Same reasoning as response_head_cb() above: an exception
            // here can only come from response_body_cb() itself, not
            // from resuming a rawstd::Task<T>.
            op->response_body_cb(
                body_item.iov(), body_item.niov(), body_item.size()
            );
        }
    } catch (const std::system_error& e) {
        if (e.code().value() == ECANCELED) {
            co_return;
        }

        // A strong self-reference here (instead of weak_ptr::lock())
        // would keep this Backend alive purely because its own recv
        // registration exists -- including while this very pump's
        // captured shared_ptr is what's being torn down as part of the
        // *owning* rawio::Queue's own destruction (e.g. process
        // shutdown), which would then call back into that same,
        // still-destructing Queue via ~Backend()'s _queue.cancel(), a
        // reentrant heap-use-after-free. A missing backend here means it
        // was already destroyed via some other, unrelated reference
        // dropping -- nothing to do.
        std::shared_ptr<Backend> backend = weak.lock();
        if (backend == nullptr) {
            co_return;
        }

        // The stream is no longer trustworthy (either a real
        // transport-level/framing error, or a cid we can't resync past):
        // fail everything still in flight and stop the pump for good.
        // _read_event must not outlive it -- ~Backend() would otherwise
        // try to cancel() an Event that's already gone.
        backend->_fail_in_flight(e.code().value());
        backend->_read_event = nullptr;
        co_return;
    } catch (const std::exception& e) {
        // Not a system_error: only reachable from
        // response_head_cb()/response_body_cb()'s own body (see above)
        // -- e.g. a std::bad_alloc. Same fate as any other error above:
        // we can no longer trust our position in the stream, so fail
        // everything in flight and stop.
        rawstd_error("_recv_pump: %s\n", e.what());

        std::shared_ptr<Backend> backend = weak.lock();
        if (backend == nullptr) {
            co_return;
        }

        backend->_fail_in_flight(EIO);
        backend->_read_event = nullptr;
        co_return;
    }
}

rawstd::Task<size_t> Backend::pread(void* buf, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<BackendOpRead> op = std::make_shared<BackendOpRead>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        buf, size, offset, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t>
Backend::preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<BackendOpReadV> op = std::make_shared<BackendOpReadV>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        iov, niov, size, offset, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t>
Backend::pwrite(const void* buf, size_t size, off_t offset, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd, sync = %d\n", fd(), size,
        (intmax_t)offset, sync
    );

    std::shared_ptr<BackendOpWrite> op = std::make_shared<BackendOpWrite>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        buf, size, offset, sync, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.sendmsg(
            fd(), op->request_msg(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd, sync = %d\n", fd(), size,
        (intmax_t)offset, sync
    );

    std::shared_ptr<BackendOpWriteV> op = std::make_shared<BackendOpWriteV>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        iov, niov, size, offset, sync, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.sendmsg(
            fd(), op->request_msg(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t> Backend::discard(size_t size, off_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<BackendOpDiscard> op = std::make_shared<BackendOpDiscard>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        size, offset, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t>
Backend::write_zeroes(size_t size, off_t offset, bool unmap, bool sync) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd, unmap = %d, sync = %d\n", fd(),
        size, (intmax_t)offset, unmap, sync
    );

    std::shared_ptr<BackendOpWriteZeroes> op =
        std::make_shared<BackendOpWriteZeroes>(
            std::static_pointer_cast<Backend>(shared_from_this()),
            _cid_counter++, size, offset, unmap, sync, trace_event
        );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<void> Backend::flush() {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('s', "fd = %d\n", fd());

    std::shared_ptr<BackendOpFlush> op = std::make_shared<BackendOpFlush>(
        std::static_pointer_cast<Backend>(shared_from_this()), _cid_counter++,
        trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_await *op;
}

} // namespace ost
} // namespace rawstor
