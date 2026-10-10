#ifndef RAWSTOR_LOCAL_MEMBER_HPP
#define RAWSTOR_LOCAL_MEMBER_HPP

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawthread/lock.hpp>

#include <atomic>
#include <memory>

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
};

std::shared_ptr<LocalMember> local_member(
    const rawstd::URI& location, const RawstdUUID& id, uint64_t offset
);

} // namespace rawstor

#endif // RAWSTOR_LOCAL_MEMBER_HPP
