#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawstd/coro.hpp>

#include <memory>

#include <cstddef>

struct RawstorObject {};

namespace rawio {
class Queue;
} // namespace rawio

namespace rawstor {

class Target;
class Chunk;

// The client-facing entity a target addresses: routes every call straight
// onto the one Chunk it wraps -- a plain target (e.g.
// ost://a,ost://b/<uuid>) is inherently a single chunk, mirrored across
// however many URIs it names. Built only by Target::open() (a friend,
// since it's the one place that actually builds a Chunk to wrap).
class Object final : public RawstorObject {
private:
    std::unique_ptr<Chunk> _chunk;

    // Object is final -- only Target::open() (a friend, since it's the
    // one place that actually builds a Chunk to wrap) ever needs this, so
    // it stays private rather than protected.
    struct Private {
        explicit Private() = default;
    };

    friend class Target;

public:
    Object(Private, std::unique_ptr<Chunk> chunk);
    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object();
    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    // This Object's own target -- the same Target the wrapped Chunk was
    // built from. Needed only by the backport shim (see
    // src/object_legacy.cpp's rawstor_object_id()/_location()).
    const Target& target() const noexcept;

    // The queue this Object was opened on -- needed only by the backport
    // shim's blocking rawstor_object_close() (see src/object_legacy.cpp),
    // which has no queue parameter of its own to pump.
    rawio::Queue& queue() const noexcept;

    rawstd::Task<size_t> pread(void* buf, size_t size, off_t offset);

    rawstd::Task<size_t>
    preadv(iovec* iov, unsigned int niov, size_t size, off_t offset);

    rawstd::Task<size_t>
    pwrite(const void* buf, size_t size, off_t offset, bool sync);

    rawstd::Task<size_t> pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync
    );

    rawstd::Task<size_t> discard(size_t size, off_t offset);

    rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync);

    rawstd::Task<void> flush();

    rawstd::Task<void> close();
};

} // namespace rawstor

#endif // RAWSTOR_OBJECT_HPP
