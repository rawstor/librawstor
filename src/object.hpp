#ifndef RAWSTOR_OBJECT_HPP
#define RAWSTOR_OBJECT_HPP

#include <rawstor/object.h>

#include <rawstd/coro.hpp>

#include <cstddef>

// Thin polymorphic base behind the opaque C handle: rawstor::Chunk (a
// single, possibly mirrored, group of slots) is its only implementation
// today, but rawstor::Volume (an MDS-backed chunked volume, docs/mds.md)
// is a second one -- routing I/O across per-chunk Chunks of its own
// rather than a Target's members directly. Every rawstor_object_*() C
// API function in object.cpp dispatches through this vtable instead of
// a fixed static_cast<Chunk*>, so both implementations are
// indistinguishable to a caller holding a RawstorObject*.
struct RawstorObject {
    virtual ~RawstorObject() = default;

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
    virtual rawstd::Task<size_t> discard(size_t size, off_t offset) = 0;
    virtual rawstd::Task<size_t>
    write_zeroes(size_t size, off_t offset, bool unmap, bool sync) = 0;
    virtual rawstd::Task<void> flush() = 0;
    virtual rawstd::Task<void> close() = 0;
};

#endif // RAWSTOR_OBJECT_HPP
