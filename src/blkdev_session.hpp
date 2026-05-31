#ifndef RAWSTOR_BLKDEV_SESSION_HPP
#define RAWSTOR_BLKDEV_SESSION_HPP

#include "session.hpp"

#include <string>

namespace rawstor {

/*
 * Shared base for local block-device storage backends (LVM, ZFS).
 *
 * Subclasses implement device_path() to map a UUID to a block device node,
 * and create()/remove() to provision/deprovision that device.
 * All I/O (pread/pwrite) and spec (BLKGETSIZE64) are handled here.
 */
class BlkdevSession : public Session {
protected:
    virtual std::string device_path(const RawstdUUID& id) const = 0;

    static int run_command(const char* const* argv);
    static int wait_for_device(const std::string& path, int timeout_ms = 5000);

public:
    BlkdevSession(rawio::Queue& queue, const rawstd::URI& location);

    void spec(
        const RawstdUUID& id,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    ) override;

    void set_object(Object* object) override;

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
