#ifndef RAWSTOR_BLK_BACKEND_HPP
#define RAWSTOR_BLK_BACKEND_HPP

#include "backend.hpp"

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/target.h>

#include <cstddef>
#include <string>

namespace rawstor {
namespace blk {

// Base for any Backend backed by a plain fd read/written via the io queue
// (rawio::Queue::pread()/pwrite()/...). Concrete backends only need to
// implement how to get from an object id to an open fd (_open()) plus
// the metadata operations (list()/create()/remove()/info()) that stay
// backend-specific; spec() has a default (BLKGETSIZE64) for backends whose
// objects are real block devices, overridden by file::Backend since its
// objects are plain regular files instead.
class Backend : public rawstor::Backend {
private:
    // Bumped whenever meta_encode()'s own field set changes -- carried as
    // this format's own leading field (see meta_encode()'s own doc
    // comment below) rather than left for a caller to track separately,
    // so every subclass rejects a record from an incompatible version
    // the same way. Private: only meta_encode()/meta_decode()'s own
    // implementation ever needs it. Bumped 1 -> 2 to add the chunk
    // placement identity fields (docs/mds.md, chunk_meta) --
    // free to break, per the design's own compatibility stance (no live
    // installations yet). Not bumped again for the `snap_version` ->
    // `snap_id` key rename, nor for dropping `volume_id`/`logical_index`/
    // `snap_id` from ChunkIdentity once the resource's own name became
    // self-describing (same unreleased line as version 2 itself --
    // nothing to stay compatible with).
    static constexpr unsigned int META_FORMAT_VERSION = 2;

    // Writes dispatched to the io queue whose completion hasn't arrived
    // yet -- see pwrite()/pwritev()'s use of it against
    // rawstor_opts_write_throttle_limit() to decide whether a write is
    // dispatched now or suspended until a slot frees up.
    unsigned int _writes_in_flight;
    // Ticket dispenser: every _throttle_acquire() call, whether it ends up
    // suspending or not, takes the next one. A suspending call's target on
    // _release_barrier below is `ticket - limit + 1` -- since every
    // acquire (immediate or queued) takes a ticket from the same
    // sequence, and every release advances the same barrier regardless of
    // whether anyone is waiting on it, the two stay in lockstep: a ticket
    // taken while under the limit is never at risk of some later,
    // unrelated release prematurely satisfying it.
    unsigned int _next_ticket;
    // Bumped once per _throttle_release() call; a suspended
    // _throttle_acquire() wakes once this reaches its own ticket's target
    // (see _next_ticket above), in ticket order -- i.e. FIFO, same
    // guarantee the old explicit waiter queue gave.
    rawstd::Barrier _release_barrier;
    // Sum of the sizes of writes currently suspended in
    // _throttle_acquire() -- see its own use of it against
    // rawstor_opts_write_backlog_capacity() to reject a write outright
    // rather than let it suspend without bound.
    size_t _pending_writes_bytes;

    // Suspends the calling coroutine until a write-dispatch slot is free
    // (see rawstor_opts_write_throttle_limit()), or throws EBUSY
    // immediately, without suspending, if queuing behind the throttle
    // would push the backlog over rawstor_opts_write_backlog_capacity().
    // Every successful return must be matched by exactly one
    // _throttle_release() call, regardless of how the dispatched write
    // itself turns out.
    rawstd::Task<void> _throttle_acquire(size_t size);
    // Releases the slot acquired by a matching _throttle_acquire() --
    // advances _release_barrier, which wakes the oldest queued waiter (by
    // ticket order), if any.
    void _throttle_release() noexcept;

protected:
    // `snap_id` is nil for the live version, or a previously-snapshotted
    // version id (docs/mds.md, "Snapshots") -- ENOTSUP on a
    // subclass without native CoW (file::Backend, lvm::Backend).
    virtual rawstd::Task<int> _open(
        const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
    ) = 0;

    // A blk-backed backend has no upfront connection step: the fd is
    // opened lazily, by _open(const RawstdUUID&) above, once
    // set_object() knows which object id to open.
    rawstd::Task<void> _connect() override final;

    // Zeroes [offset, offset + size) of `target_fd` -- shared by
    // write_zeroes() below (target_fd = fd(), this instance's own open
    // object) and a subclass's own create-time zero-fill of a freshly
    // allocated object, before it's revealed under its real name (e.g.
    // lvm::Backend::create()), where target_fd is unrelated to this
    // instance's own fd()/set_fd() state. Tries FALLOC_FL_ZERO_RANGE
    // (unmap=false) or FALLOC_FL_PUNCH_HOLE (unmap=true) first --
    // typically hardware-accelerated (WRITE_ZEROES/discard) -- and logs
    // a warning before falling back to an explicit zero-fill write loop
    // if the backing store doesn't support fallocate() at all.
    rawstd::Task<void>
    _zero_fill(int target_fd, off_t offset, size_t size, bool unmap);

    // True if `path` currently names something (any type) in the
    // backing store; false only for ENOENT. Shared by lvm::Backend/
    // zfs::Backend's create()/remove() to make retrying either one
    // against the same id idempotent, instead of a shell-out command
    // rejecting an already-there/already-gone object with a generic,
    // retryable EIO.
    rawstd::Task<bool> _exists(const std::string& path);

    // Upper bound on meta_encode()'s own return value, comfortably
    // covering every field at its widest (a full 16 hex digits for each
    // uint64_t one, a full 36-char dashed UUID for volume_id). Protected
    // (not private): file::Backend, the only subclass that needs it,
    // sizes its own fixed-length on-disk .meta record to this constant
    // instead of guessing; nothing outside the class hierarchy needs it,
    // unlike meta_encode()/meta_decode() themselves (public further
    // down, for tests/).
    static constexpr size_t META_MAX_SIZE = 400;

public:
    // The chunk placement identity persisted alongside the mirror
    // consistency state (docs/mds.md, chunk_meta): stamped once
    // at create(), immutable afterwards -- set_sync_state() must read
    // the existing record and carry this part through unchanged rather
    // than reset it, since it never receives this identity itself (see
    // RawstorObjectSyncState, which deliberately doesn't carry it).
    // member_kind all-zero (RAWSTOR_MEMBER_DATA) is a standalone
    // (non-chunk) object -- today's only case, until Volume creation
    // starts stamping real values. `volume_id`/`snap_id`/`logical_index`
    // used to live here too, but the resource's own on-disk/LV/zvol name
    // is now self-describing (`id` is the volume's own id directly,
    // `chunk_offset` -- threaded alongside `id` through every method
    // below -- disambiguates chunks of the same volume, see
    // rawstor::ListedObject's own doc comment in backend.hpp), so nothing
    // here needs to duplicate them.
    struct ChunkIdentity {
        RawstorMemberKind member_kind = RAWSTOR_MEMBER_DATA;
        uint8_t width = 0;
        uint64_t chunk_size = 0;
    };

    Backend(Private p, rawio::Queue& queue, const rawstd::URI& location);

    rawstd::Task<void> close() override final;

    rawstd::Task<void> set_object(
        const RawstdUUID& id, uint64_t chunk_offset,
        const RawstdUUID& snap_id = {}
    ) override final;

    // Default spec() for a backend whose object id maps to a real block
    // device (BLKGETSIZE64) -- file::Backend overrides this instead, since
    // its objects are plain regular files.
    rawstd::Task<RawstorObjectSpec>
    spec(const RawstdUUID& id, uint64_t chunk_offset) override;

    // Encodes/decodes a RawstorObjectSyncState plus its ChunkIdentity as
    // a compact colon-separated string of hex fields, e.g.
    // "version=2:state=0:epoch=0:sync_id=0:h0=0:h1=0:h2=0:h3=0:
    // member_kind=0:width=0:volume_id=00000000-0000-0000-0000-000000000000:
    // logical_index=0:chunk_size=0:snap_id=0" -- shared by every
    // blk-backed subclass's own native per-copy metadata storage:
    // lvm::Backend's LVM tag, zfs::Backend's ZFS user property, and
    // file::Backend's own on-disk .meta file (NUL-padded out to
    // META_MAX_SIZE bytes -- see its own doc comment for why). Only
    // characters valid in all three are used (no comma, no whitespace).
    // Public (not protected) so tests/ can exercise them directly
    // without a real lvm/zfs/file backend of their own.
    //
    // meta_decode() reverses meta_encode(), throwing EPROTO if value is
    // not a well-formed encoding of the current META_FORMAT_VERSION
    // (including an empty string: the caller must not mistake "no value
    // was ever recorded" for a valid record, and a record from a
    // different format version, which this repo will never write again
    // once it's bumped).
    static std::string meta_encode(
        const RawstorObjectSyncState& sync_state, const ChunkIdentity& identity
    );
    static void meta_decode(
        const std::string& value, RawstorObjectSyncState* sync_state,
        ChunkIdentity* identity
    );

    // No universal answer for a raw block device -- left pure virtual
    // (inherited from rawstor::Backend) rather than given a default here,
    // so a new blk::Backend subclass that forgets to implement native
    // per-copy metadata (docs/mirroring.md's "native per-copy mirror
    // metadata" stage) fails to compile instead of silently bypassing the
    // mirror's split-brain-exclusion mechanism at runtime. file::Backend/
    // lvm::Backend/zfs::Backend each provide their own real implementation.

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

    rawstd::Task<size_t> discard(size_t size, off_t offset) override final;

    rawstd::Task<size_t> write_zeroes(
        size_t size, off_t offset, bool unmap, bool sync
    ) override final;

    rawstd::Task<void> flush() override final;

    // For tests/ to verify write-throttling (see pwrite()/pwritev() and
    // _throttle_acquire()) without depending on real storage-completion
    // timing.
    inline unsigned int writes_in_flight() const noexcept {
        return _writes_in_flight;
    }

    // For tests/ to verify the write backlog cap (see _throttle_acquire()).
    inline size_t pending_writes_bytes() const noexcept {
        return _pending_writes_bytes;
    }
};

} // namespace blk
} // namespace rawstor

#endif // RAWSTOR_BLK_BACKEND_HPP
