#include "zfs_session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

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
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::string dataset = _parent_dataset + "/" + uuid_str;

    char size_buf[64];
    snprintf(size_buf, sizeof(size_buf), "%zu", sp.size);

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
