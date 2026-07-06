#include "zfs_session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>

namespace rawstor {
namespace zfs {

static std::string parse_parent_dataset(const rawstd::URI& location) {
    if (location.scheme() != "zfs") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!location.host().empty()) {
        rawstd_error("Empty host expected: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::string path = location.path().str();
    if (path.empty() || path == "/") {
        rawstd_error(
            "Parent dataset is empty in URI: %s\n", location.str().c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    /* Strip leading slash: /tank/rawstor → tank/rawstor */
    if (path.front() == '/') {
        path = path.substr(1);
    }
    return path;
}

Session::Session(rawio::Queue& queue, const rawstd::URI& location) :
    BlkdevSession(queue, location),
    _parent_dataset(parse_parent_dataset(location)) {
}

std::string Session::device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << "/dev/zvol/" << _parent_dataset << "/" << uuid_str;
    return oss.str();
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    /*
     * zfs-create(8) rejects volume sizes that are not a multiple of
     * volblocksize (16 KiB by default, 8 KiB on older OpenZFS), so round
     * the requested size up front.
     */
    const uint64_t volblocksize = 16384;

    if (sp.size == 0 || sp.size > UINT64_MAX - (volblocksize - 1)) {
        rawstd_error("zfs: invalid object size: %" PRIu64 "\n", sp.size);
        cb(EINVAL);
        return;
    }

    uint64_t size = (sp.size + volblocksize - 1) / volblocksize * volblocksize;
    if (size != sp.size) {
        rawstd_info(
            "zfs: rounding volume size up from %" PRIu64 " to %" PRIu64
            " bytes\n",
            sp.size, size
        );
    }

    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::string dataset = _parent_dataset + "/" + uuid_str;

    char size_buf[64];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64, size);

    rawstd_info(
        "zfs: creating zvol %s, size %s bytes\n", dataset.c_str(), size_buf
    );

    run_async(
        {"zfs", "create", "-V", size_buf, dataset}, device_path(id),
        [dataset, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "zfs: failed to create zvol %s: %s\n", dataset.c_str(),
                    strerror(error)
                );
            }
            cb(error);
        }
    );
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::string dataset = _parent_dataset + "/" + uuid_str;

    rawstd_info("zfs: destroying zvol %s\n", dataset.c_str());

    run_async(
        {"zfs", "destroy", dataset}, "",
        [dataset, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "zfs: failed to destroy zvol %s: %s\n", dataset.c_str(),
                    strerror(error)
                );
            }
            cb(error);
        }
    );
}

} // namespace zfs
} // namespace rawstor
