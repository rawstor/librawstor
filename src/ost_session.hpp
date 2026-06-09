#ifndef RAWSTOR_OST_SESSION_HPP
#define RAWSTOR_OST_SESSION_HPP

#include "session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/ringbuf.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/ost_protocol.h>
#include <rawstor/rawstor.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

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

    int _connect();
    void _set_object(Object* object);
    void _fail_in_flight(int error, bool* next_head, size_t* next_size);
    SessionOp& _find_op(uint16_t cid);
    void _add_op(const std::shared_ptr<SessionOp>& op);
    void _remove_op(uint16_t cid);

public:
    Session(rawio::Queue& queue, const rawstd::URI& location);
    ~Session();

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;

    void spec(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) override;

    void set_object(Object* object) override;

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwrite(
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override;
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_OST_SESSION_HPP
