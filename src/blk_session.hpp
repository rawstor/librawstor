#ifndef RAWSTOR_BLK_SESSION_HPP
#define RAWSTOR_BLK_SESSION_HPP

#include "session.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>

namespace rawstor {
namespace blk {

// Base for any Session backed by a plain fd read/written via the io queue
// (rawio::Queue::pread()/pwrite()/...). Concrete backends only need to
// implement how to get from an object id to an open fd (_connect()) plus
// the metadata operations (list()/create()/remove()/spec()/info()), which
// stay backend-specific.
class Session : public rawstor::Session {
protected:
    virtual int _connect(const RawstdUUID& id) = 0;

public:
    Session(Private p, rawio::Queue& queue, const rawstd::URI& location);

    // A blk-backed session has no upfront connection step: the fd is
    // opened lazily, by _connect(), once set_object() knows which object
    // id to open.
    rawstd::Task<void> open() override final;

    rawstd::Task<void> close() override final;

    rawstd::Task<void> set_object(Object* object) override final;

    rawstd::Task<size_t>
    pread(void* buf, size_t size, off_t offset) override final;

    rawstd::Task<size_t> preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset
    ) override final;

    rawstd::Task<size_t> pwrite(
        const void* buf, size_t size, off_t offset, bool sync
    ) override final;

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) override final;

    rawstd::Task<void> flush() override final;
};

} // namespace blk
} // namespace rawstor

#endif // RAWSTOR_BLK_SESSION_HPP
