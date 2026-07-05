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
 * and create()/remove() to provision/deprovision that device.
 * All I/O (pread/pwrite) and meta (BLKGETSIZE64) are handled here.
 *
 * meta() reports the actual device size: LVM rounds the requested size up
 * to the VG extent size, and zfs-create(8) rejects sizes that are not a
 * multiple of volblocksize. The file backend reports the requested size
 * verbatim, so the specs of a mixed file/blkdev mirror may disagree.
 */
class BlkdevSession : public Session {
protected:
    virtual std::string device_path(const RawstdUUID& id) const = 0;

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
    BlkdevSession(rawio::Queue& queue, const rawstd::URI& location);

    void meta(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectMeta&, int)>&& cb
    ) override;

    void set_state(
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        std::function<void(int)>&& cb
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
