#ifndef RAWSTOR_OST_SESSION_HPP
#define RAWSTOR_OST_SESSION_HPP

#include "session.hpp"

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

class SessionOp;

class Session final : public rawstor::Session {
    friend class SessionOp;

private:
    uint16_t _cid_counter;

    rawio::Event* _read_event;
    std::unordered_map<uint16_t, std::shared_ptr<SessionOp>> _ops;

    rawstd::Task<void> _open() override;
    rawstd::Task<int> _connect();
    rawstd::Task<void> _set_object(Object* object);
    // The cid-dispatched counterpart of the old basic_request_async():
    // sends a RawstorOSTFrameBasic-shaped request (list/create/remove/
    // spec/info/set_object all share this shape) and awaits its response
    // through the same _ops demultiplex mechanism as every other op --
    // requires _recv_pump to already be running, i.e. _open() to have
    // completed.
    template <typename T = char>
    rawstd::Task<std::vector<T>> _basic_request(
        RawstorOSTCommandType cmd, const char* op_name, const RawstdUUID& id,
        uint64_t val
    );
    void _fail_in_flight(int error);
    // Returns nullptr, rather than throwing, for an unregistered cid: a
    // response can legitimately race with Connection::_op() already having
    // failed and retried that same op on a different session (e.g. after a
    // send-side error on this connection), in which case the cid was
    // already unregistered and the response is stale, not a corrupted
    // stream.
    SessionOp* _find_op(uint16_t cid);
    void _add_op(const std::shared_ptr<SessionOp>& op);
    void _remove_op(uint16_t cid);

    // Pulls the shared response stream forever, demultiplexing each
    // delivery by cid into whichever SessionOp is waiting for it -- the
    // coroutine-era replacement for set_object()'s old recv_multishot
    // callback. A free-standing detached loop keyed off a weak_ptr, not a
    // member coroutine capturing `this`/a strong shared_ptr, for the same
    // reason the old callback captured a weak_ptr: it must not keep this
    // Session alive purely because its own recv registration exists (see
    // the .cpp for the full reentrant-teardown reasoning).
    static rawstd::DetachedTask _recv_pump(
        std::weak_ptr<Session> weak, rawio::RecvStream stream,
        rawstd::TraceEvent trace_event
    );

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);
    ~Session();

    rawstd::Task<void> close() override;

    rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) override;

    rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) override;

    rawstd::Task<void> remove(const RawstdUUID& id) override;

    rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) override;

    rawstd::Task<RawstorLocationInfo> info() override;

    rawstd::Task<void> set_object(Object* object) override;

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) override;

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) override;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) override;

    rawstd::Task<void> flush() override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_SESSION_HPP
