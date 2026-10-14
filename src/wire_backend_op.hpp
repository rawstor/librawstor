#ifndef RAWSTOR_WIRE_BACKEND_OP_HPP
#define RAWSTOR_WIRE_BACKEND_OP_HPP

#include "telemetry.hpp"
#include "wire_backend.hpp"

#include <rawstd/gpp.hpp>

#include <cassert>
#include <cerrno>
#include <cstring>

namespace rawstor {
namespace wire {

inline int validate_result(size_t size, size_t result) noexcept {
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
// is_permanent_backend_error() (see slot.cpp) already knows can
// never succeed on retry. EBADMSG is one such body.res value: the OST
// server sends it (see ost/src/client.cpp) only when the payload it just
// received doesn't hash to what the client declared, meaning the client
// and server have lost agreement on where in the byte stream the current
// frame even ends -- reconnecting is what recovers alignment on the next
// frame header, same as for a magic mismatch below.
inline int validate_response(const RawstorFrameResponse* response) noexcept {
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

inline int
validate_cmd(RawstorCommandType cmd, RawstorCommandType expected) noexcept {
    if (cmd == expected) {
        return 0;
    }

    rawstd_error("Unexpected command: %d\n", cmd);
    return EPROTO;
}

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
    uint64_t _op_offset;

    rawstd::TraceEvent _trace_event;
    // A strong reference, not just a back-pointer: a BackendOp can outlive
    // Backend::_ops's own copy of it (e.g. a still-pending send/sendmsg
    // completion keeps a BackendOp alive independently, via its own
    // captured shared_ptr, even after the owning Backend is gone from
    // Slot::_backends and its _ops member has been destroyed). This
    // keeps the Backend itself alive for as long as any BackendOp -- in
    // _ops or floating in a pending completion closure -- still needs it.
    std::shared_ptr<rawstor::wire::Backend> _backend;
    RawstorFrameResponse _response;

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
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        const rawstd::TraceEvent& trace_event, const char* op_name,
        size_t op_size, uint64_t op_offset
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
    response_head_cb(const RawstorFrameResponse* response, int error) = 0;

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

} // namespace wire
} // namespace rawstor

#endif // RAWSTOR_WIRE_BACKEND_OP_HPP
