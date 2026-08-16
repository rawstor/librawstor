#ifndef RAWSTOR_BLKDEV_SESSION_HPP
#define RAWSTOR_BLKDEV_SESSION_HPP

#include "blk_session.hpp"

#include <rawstd/gpp.hpp>

#include <cerrno>
#include <cstdint>
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
class BlkdevSession : public blk::Session {
protected:
    virtual std::string device_path(const RawstdUUID& id) const = 0;

    void _connect(
        const RawstdUUID& id, uint64_t snap, std::function<void(int)>&& cb
    ) override;

    /* Live device size via BLKGETSIZE64; backs both spec() and meta(). */
    void _size(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(uint64_t, int)>&& cb
    );

    /*
     * Device node of one version: snap = 0 is the live device. The base
     * implementation supports only the live version — a backend with
     * native CoW (zfs) overrides it; the rest answer ENOTSUP by
     * construction.
     */
    virtual std::string device_path(const RawstdUUID& id, uint64_t snap) const {
        if (snap != 0) {
            RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
        }
        return device_path(id);
    }

    /*
     * Reads the mirror consistency state (state/epoch/sync_id/history) for
     * one version of id via the backend's native storage (snap = 0 is the
     * live copy; a snapshot's state is frozen at snapshot time). The size
     * field of the returned meta is ignored by the caller (meta()
     * overwrites it with the device size). Must fail (not fabricate
     * CLEAN) when no state has ever been recorded: an untrusted member is
     * always safer than a trusted one that happens to be wrong
     * (docs/mirroring.md, case F10 — the caller already treats any meta()
     * error as "member stale, needs a resync").
     */
    virtual void _meta_identity(
        const RawstdUUID& id, uint64_t snap,
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
    BlkdevSession(Private p, rawio::Queue& queue, const rawstd::URI& location);

    /*
     * Enumerating and sizing a VG / dataset means asking LVM or ZFS, not
     * the fd layer, so neither is answerable here; the block-device
     * backends report them as unsupported.
     */
    void list(
        unsigned int limit, const RawstdUUID& token,
        std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&&
            cb
    ) override;

    void
    info(std::function<void(const RawstorLocationInfo&, int)>&& cb) override;

    void spec(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) override;

    void meta(
        const RawstdUUID& id, uint64_t snap,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;
};

} // namespace rawstor

#endif // RAWSTOR_BLKDEV_SESSION_HPP
