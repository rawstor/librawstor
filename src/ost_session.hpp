#ifndef RAWSTOR_OST_SESSION_HPP
#define RAWSTOR_OST_SESSION_HPP

#include "session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/ringbuf.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

#include <functional>
#include <list>
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

    RawIOEvent* _read_event;
    std::unordered_map<uint16_t, std::shared_ptr<SessionOp>> _ops;

    void _set_object(Object* object, std::function<void(int)>&& cb);
    // Arms the multishot recv that demultiplexes responses to in-flight
    // ops; called once SET_OBJECT has been acknowledged.
    void _arm_recv();
    void _fail_in_flight(int error, bool* next_head, size_t* next_size);
    // Returns nullptr, rather than throwing, for an unregistered cid: a
    // response can legitimately race with Connection::_op() already having
    // failed and retried that same op on a different session (e.g. after a
    // send-side error on this connection), in which case the cid was
    // already unregistered and the response is stale, not a corrupted
    // stream.
    SessionOp* _find_op(uint16_t cid);
    void _add_op(const std::shared_ptr<SessionOp>& op);
    void _remove_op(uint16_t cid);
    void _basic(
        RawstorOSTCommandType cmd, const RawstdUUID& id, uint64_t val,
        std::function<void(int)>&& cb
    );

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);
    ~Session();

    void list(
        unsigned int limit, const RawstdUUID& token,
        std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&&
            cb
    ) override;
    void connect(std::function<void(int)>&& cb) override;

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;

    void spec(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) override;

    void meta(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;

    void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    ) override;

    void
    info(std::function<void(const RawstorLocationInfo&, int)>&& cb) override;

    void set_object(Object* object, std::function<void(int)>&& cb) override;

    void flush(std::function<void(int)>&& cb) override;

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwrite(
        const void* buf, size_t size, off_t offset, bool sync,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync, std::function<void(size_t, int)>&& cb
    ) override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_SESSION_HPP
