#ifndef RAWSTOR_OST_SESSION_HPP
#define RAWSTOR_OST_SESSION_HPP

#include "session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/ringbuf.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

#include <functional>
#include <memory>
#include <string>
#include <unordered_map>

#include <cstddef>

namespace rawstor {
namespace ost {

class Context;

class Session final : public rawstor::Session {
private:
    uint16_t _cid_counter;

    std::shared_ptr<Context> _context;

    /* SET_OBJECT (the handshake) was exchanged on this connection. */
    bool _handshaken;

    void _basic(
        RawstorOSTCommandType cmd, const RawstdUUID& id, uint64_t val,
        std::function<void(int)>&& cb
    );

    /*
     * Routes a zero-payload basic command through the multishot receive
     * context when the session is object-bound, or the plain pre-open
     * exchange (with the lazy handshake) when it is not.
     */
    void _basic_or_op(
        RawstorOSTCommandType cmd, const RawstdUUID& id, uint64_t val,
        std::function<void(int)>&& cb
    );

    void _allocate(
        const RawstdUUID& id, const RawstorObjectSpec& spec,
        std::function<void(int)>&& cb
    );

    /*
     * SET_OBJECT exchange: version/features handshake plus the object
     * binding; id == nullptr sends a null binding (control connection).
     * val is the bound snapshot version (0 = live).
     */
    void _set_object_exchange(
        const RawstdUUID* id, uint64_t val, std::function<void(int)>&& cb
    );

    /*
     * SET_OBJECT must be the first command on a connection: control
     * operations issued before an object is bound handshake lazily with a
     * null binding.
     */
    void _ensure_handshake(std::function<void(int)>&& cb);

    /* Plain pre-open exchanges, valid only after the handshake. */
    void _meta_exchange(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    );
    void _set_state_exchange(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    );
    void _list_exchange(
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    );

public:
    Session(rawio::Queue& queue, const rawstd::URI& location);
    ~Session();

    void connect(std::function<void(int)>&& cb) override;

    void create(
        const RawstdUUID& id, const RawstorObjectSpec& sp,
        std::function<void(int)>&& cb
    ) override;

    void remove(const RawstdUUID& id, std::function<void(int)>&& cb) override;

    void meta(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;

    void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
    ) override;

    /*
     * Valid on an unbound (control) connection only: the reconstruct scan
     * always opens a fresh one (Connection::list).
     */
    void list(
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
    ) override;

    void snapshot(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;

    void snap_remove(
        const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
    ) override;

    void set_object(Object* object, std::function<void(int)>&& cb) override;

    void flush(std::function<void(size_t, int)>&& cb) override;

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
