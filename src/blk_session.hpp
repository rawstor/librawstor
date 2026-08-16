#ifndef RAWSTOR_BLK_SESSION_HPP
#define RAWSTOR_BLK_SESSION_HPP

#include "session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>

#include <functional>

namespace rawstor {
namespace blk {

// Base for any Session backed by a plain fd read/written via the io queue
// (rawio::Queue::pread()/pwrite()/...). Concrete backends only need to
// implement how to get from an object id to an open fd (_connect()) plus
// the metadata operations (list()/create()/remove()/spec()/info()), which
// stay backend-specific.
class Session : public rawstor::Session {
protected:
    /*
     * Opens the fd backing `id`. Completes with the open fd, or with a
     * negative errno value on failure. Backends whose open can block (a
     * suspended DM device, a busy pool) submit it to the io queue rather
     * than calling open(2) inline.
     */
    virtual void
    _connect(const RawstdUUID& id, std::function<void(int)>&& cb) = 0;

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);

    void set_object(Object* object, std::function<void(int)>&& cb)
        override final;

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override final;

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    ) override final;

    void pwrite(
        const void* buf, size_t size, off_t offset, bool sync,
        std::function<void(size_t, int)>&& cb
    ) override final;

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync, std::function<void(size_t, int)>&& cb
    ) override final;

    void flush(std::function<void(int)>&& cb) override final;
};

} // namespace blk
} // namespace rawstor

#endif // RAWSTOR_BLK_SESSION_HPP
