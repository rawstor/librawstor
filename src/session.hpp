#ifndef RAWSTOR_SESSION_HPP
#define RAWSTOR_SESSION_HPP

#include "object.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>

#include <memory>
#include <string>
#include <vector>

namespace rawstor {

class Session : public std::enable_shared_from_this<Session> {
private:
    rawstd::URI _location;
    int _fd;

protected:
    struct Private {
        explicit Private() = default;
    };

    rawio::Queue& _queue;

    inline void set_fd(int fd) noexcept { _fd = fd; }

    // Establishes whatever this backend needs before any other call
    // below is usable (e.g. the OST backend's TCP connect + the start of
    // its response demultiplex pump). Called exactly once by create(),
    // before it hands the Session back.
    virtual rawstd::Task<void> _connect() = 0;

public:
    // Constructs the right backend for `location`'s scheme and
    // _connect()s it -- the returned Session is immediately usable.
    static rawstd::Task<std::shared_ptr<Session>>
    create(rawio::Queue& queue, const rawstd::URI& location);

    Session(Private, rawio::Queue& queue, const rawstd::URI& location);
    Session(const Session&) = delete;
    Session(Session&&) noexcept = delete;
    virtual ~Session();
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    std::string str() const;

    inline const rawstd::URI& location() const noexcept { return _location; }

    inline int fd() const noexcept { return _fd; }

    // Tears down what _connect() set up. Not called implicitly by
    // ~Session() (a coroutine can't run in a destructor) -- callers that
    // want a graceful async teardown must co_await this themselves.
    virtual rawstd::Task<void> close() = 0;

    // `targets`: overwritten with this page's UUIDs. `token`: this
    // call's pagination cursor on entry, overwritten with the next
    // page's cursor on return (zeroed once there's nothing left).
    virtual rawstd::Task<void> list(
        unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
    ) = 0;

    virtual rawstd::Task<void>
    create(const RawstdUUID& id, const RawstorObjectSpec& sp) = 0;

    virtual rawstd::Task<void> remove(const RawstdUUID& id) = 0;

    virtual rawstd::Task<RawstorObjectSpec> spec(const RawstdUUID& id) = 0;

    virtual rawstd::Task<RawstorLocationInfo> info() = 0;

    virtual rawstd::Task<void> set_object(Object* object) = 0;

    virtual rawstd::Task<size_t>
    pread(void* buf, size_t size, off_t offset) = 0;

    virtual rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset) = 0;

    virtual rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync) = 0;

    virtual rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    ) = 0;

    // Hints that [offset, offset + size) is no longer in use -- a pure
    // optimization (space reclamation), never a correctness requirement:
    // unlike write_zeroes() below, discard() does *not* guarantee the
    // range reads back as zero afterward. Returns the number of bytes
    // covered by the hint, mirroring pwrite()'s own byte-count result.
    virtual rawstd::Task<size_t> discard(size_t size, off_t offset) = 0;

    // Zeroes [offset, offset + size) -- unlike discard() above, the range
    // is guaranteed to read back as zero once this completes. `unmap`
    // hints that the backend may (not must) deallocate the underlying
    // storage for the zeroed range, same as virtio-blk's
    // VIRTIO_BLK_WRITE_ZEROES_FLAG_UNMAP.
    virtual rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap) = 0;

    virtual rawstd::Task<void> flush() = 0;
};

} // namespace rawstor

#endif // RAWSTOR_SESSION_HPP
