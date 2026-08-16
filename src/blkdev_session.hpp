#ifndef RAWSTOR_BLKDEV_SESSION_HPP
#define RAWSTOR_BLKDEV_SESSION_HPP

#include "blk_session.hpp"

#include <functional>
#include <string>
#include <vector>

namespace rawstor {

/*
 * Shared base for local block-device storage backends (LVM, ZFS).
 *
 * Subclasses implement device_path() to map a UUID to a block device node,
 * and create()/remove() to provision/deprovision that device.
 * All I/O (pread/pwrite) and spec (BLKGETSIZE64) are handled here.
 *
 * spec() reports the actual device size: LVM rounds the requested size up
 * to the VG extent size, and zfs-create(8) rejects sizes that are not a
 * multiple of volblocksize. The file backend reports the requested size
 * verbatim, so the specs of a mixed file/blkdev mirror may disagree.
 */
class BlkdevSession : public blk::Session {
protected:
    virtual std::string device_path(const RawstdUUID& id) const = 0;

    void
    _connect(const RawstdUUID& id, std::function<void(int)>&& cb) override;

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
};

} // namespace rawstor

#endif // RAWSTOR_BLKDEV_SESSION_HPP
