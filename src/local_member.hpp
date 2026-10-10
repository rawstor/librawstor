#ifndef RAWSTOR_LOCAL_MEMBER_HPP
#define RAWSTOR_LOCAL_MEMBER_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/target.h>

#include <rawthread/condition.hpp>
#include <rawthread/lock.hpp>

#include <atomic>
#include <map>
#include <memory>
#include <mutex>
#include <utility>
#include <vector>

#include <cstdint>

namespace rawstor {

/*
 * One copy of a chunk stored by this process: a file://, lvm:// or zfs://
 * location this process opens, directly or for the clients of its
 * rawstor-ost. Every open of that copy in the process shares one, found
 * by location, object id and chunk offset, so the copy keeps its own
 * DIRTY/CLEAN/LOST (docs/mirroring.md, "DIRTY, CLEAN and LOST") the same
 * whichever of its sessions a request comes through.
 */
struct LocalMember {
    // Serializes every change to the copy's record (SET_CONFIG, the copy's
    // own DIRTY/CLEAN/LOST): each reads the record, decides, and writes it
    // back with fsync as one step.
    rawthread::Lock record;
    // Sessions open for writing on the copy right now. Changed only with
    // `record` held: a session joins before its first write, so a
    // departure that finds none left can mark the copy CLEAN without
    // racing a write.
    std::atomic<uint32_t> writers{0};
    // The record is known not to be CLEAN: a write needs no DIRTY mark of
    // its own. Read without the lock, set and cleared with it held.
    std::atomic<bool> dirty{false};

    /*
     * Fencing (docs/multiattach.md, "Epoch on writes"): writes stamped
     * with an epoch below the copy's accepted configuration are refused.
     * A write is admitted under the current generation and counted there
     * until it completes; raise_epoch() moves to the next generation and
     * waits for the previous one to drain, so nothing admitted under the
     * old configuration lands once the new one is recorded. Writes
     * stamped 0 are never fenced and never counted.
     */

    // Raises the known epoch to `epoch` without waiting for anything:
    // learning the copy's own record, nothing to drain against.
    void learn_epoch(uint64_t epoch) noexcept;

    // Admits a write stamped `epoch`: false if it is below the copy's
    // epoch. On success the write counts in `generation` until release().
    bool admit(uint64_t epoch, uint64_t& generation) noexcept;
    void release(uint64_t generation) noexcept;

    // Called with `record` held, before a record with `epoch` is
    // persisted: from now on writes stamped below it are refused, and this
    // returns once every write admitted under an older one has completed.
    // While it waits for them it lets go of `record` -- one of them may
    // need it for its DIRTY mark -- and takes it back before returning;
    // true then, and the caller reads the record anew.
    rawstd::Task<bool> raise_epoch(rawio::Queue& queue, uint64_t epoch);

    /*
     * Resync across processes (docs/multiattach.md, "Resync across
     * processes"): while the copy's role is SYNCING, the sectors (512
     * bytes) client writes reached since it became SYNCING, so that a
     * resync's own copy (a RESYNC write) never overwrites one of them. A
     * client write covering a sector only in part leaves it to the copy.
     * The record lives in memory only: a copy that has none -- not
     * SYNCING, or SYNCING since before this process started -- refuses
     * RESYNC writes, and the resync starts over from a configuration that
     * marks the copy SYNCING again.
     */

    // Called with `record` held whenever the copy records a
    // configuration, with the copy's own role in it. Becoming SYNCING
    // starts an empty record (a resync starts: nothing is known to be
    // written yet); staying SYNCING keeps it; any other role drops it.
    void follow_role(RawstorObjectMemberRole role) noexcept;

    // Before a client write of [offset, offset + size) goes out: waits for
    // an overlapping RESYNC write still in flight, then records the
    // sectors the write covers whole. A no-op while the copy keeps no
    // record.
    rawstd::Task<void>
    client_write(rawio::Queue& queue, uint64_t offset, uint64_t size);

    using Ranges = std::vector<std::pair<uint64_t, uint64_t>>;

    // A RESYNC write of [offset, offset + size): false if the copy keeps no
    // record. Otherwise `runs` are the ranges in it no client write
    // reached, to be written, and the whole range counts as in flight
    // until resync_end().
    bool resync_begin(uint64_t offset, uint64_t size, Ranges& runs);
    void resync_end(uint64_t offset, uint64_t size) noexcept;

private:
    std::atomic<uint64_t> _epoch{0};
    std::atomic<uint64_t> _generation{0};
    std::atomic<int64_t> _admitted[2] = {0, 0};
    std::mutex _drain_mu;
    rawthread::Condition _drain_waiters;

    std::atomic<bool> _syncing{false};
    std::mutex _resync_mu;
    // Written sectors, one bitmap of 2048 sectors per 1 MiB region,
    // allocated only for regions a client write reached.
    std::map<uint64_t, std::vector<uint64_t>> _written;
    // RESYNC writes in flight, [begin, end).
    Ranges _resyncing;
    rawthread::Condition _resync_waiters;
};

std::shared_ptr<LocalMember> local_member(
    const rawstd::URI& location, const RawstdUUID& id, uint64_t offset
);

} // namespace rawstor

#endif // RAWSTOR_LOCAL_MEMBER_HPP
