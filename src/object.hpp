#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawstd/coro.hpp>

#include <memory>

#include <cstddef>

struct RawstorObject {};

namespace rawstor {

class Target;
class Chunk;

/*
 * The client-facing entity a target addresses: routes every call
 * straight onto the one Chunk it wraps -- a plain target (e.g.
 * ost://a,ost://b/<uuid>) is inherently a single chunk, mirrored across
 * however many URIs it names. Built only by Target::open() (a friend, by
 * analogy with Chunk's own relationship to Target).
 */
class Object final : public RawstorObject {
private:
    std::unique_ptr<Chunk> _chunk;

    // Object is final -- only Target::open() (a friend, since it's the
    // one place that actually builds a Chunk to wrap) ever needs this,
    // so it stays private rather than protected.
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
