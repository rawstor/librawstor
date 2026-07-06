#ifndef RAWSTOR_BLKDEV_SESSION_HPP
#define RAWSTOR_BLKDEV_SESSION_HPP

#include "session.hpp"

#include <functional>
#include <string>
#include <vector>

namespace rawstor {

/*
 * Shared base for local block-device storage backends (LVM, ZFS).
 *
 * Subclasses implement device_path() to map a UUID to a block device node,
 * create()/remove() to provision/deprovision that device, and
 * _meta_identity()/set_state() to read/write the mirror consistency state
 * (state/epoch/sync_id/history) using whatever native mechanism the backend
 * offers (ZFS user properties, LVM tags) — there is nowhere to put a sidecar
 * file next to a raw block device. All I/O (pread/pwrite) and the size half
 * of meta() (BLKGETSIZE64) are handled here.
 *
 * meta() reports the actual device size: LVM rounds the requested size up
 * to the VG extent size, and zfs-create(8) rejects sizes that are not a
 * multiple of volblocksize. The file backend reports the requested size
 * verbatim, so the specs of a mixed file/blkdev mirror may disagree. The
 * consistency-state fields never come from the device itself, so they are
 * left to _meta_identity() untouched.
 */
class BlkdevSession : public Session {
protected:
    virtual std::string device_path(const RawstdUUID& id) const = 0;

    /*
     * Reads the mirror consistency state (state/epoch/sync_id/history) for
     * id via the backend's native storage. The size field of the returned
     * meta is ignored by the caller (meta() overwrites it with the live
     * device size). Must fail (not fabricate CLEAN) when no state has ever
     * been recorded: an untrusted member is always safer than a trusted
     * one that happens to be wrong (docs/mirroring.md, case F10 — the
     * caller already treats any meta() error as "member stale, needs a
     * resync").
     */
    virtual void _meta_identity(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) = 0;

    /*
     * Spawns cmd with posix_spawnp() and observes its exit by polling a
     * pidfd on the queue; optionally waits for wait_path to appear as a
     * block device afterwards (bounded by rawstor_opts_wait_device_timeout).
     * Nothing blocks the event loop. cb is invoked from a queue completion
     * callback with 0 on success or a positive errno value on failure.
     */
    void run_async(
        std::vector<std::string> cmd, std::string wait_path,
        std::function<void(int)>&& cb
    );

    /*
     * Like run_async(), but captures the child's stdout instead of waiting
     * for a device path: used for the query side of native metadata storage
     * ("zfs get", "lvs -o lv_tags"). cb is invoked with the captured output
     * (stripped of nothing — trailing newline included) and 0 on a
     * zero-exit-status child, or an empty string and a positive errno
     * value on failure.
     */
    void run_async_capture(
        std::vector<std::string> cmd, std::function<void(std::string, int)>&& cb
    );

public:
    BlkdevSession(rawio::Queue& queue, const rawstd::URI& location);

    void meta(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;

    void set_object(Object* object, std::function<void(int)>&& cb) override;

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

} // namespace rawstor

#endif // RAWSTOR_BLKDEV_SESSION_HPP
