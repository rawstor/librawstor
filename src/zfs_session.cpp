#include "zfs_session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <stdexcept>
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

    char size_arg[64];
    snprintf(size_arg, sizeof(size_arg), "%zu", sp.size);

    rawstd_info(
        "zfs: creating zvol %s, size %s bytes\n", dataset.c_str(), size_arg
    );

    const char* argv[] = {"zfs",    "create",        "-V",
                          size_arg, dataset.c_str(), nullptr};

    int res = run_command(argv);
    if (res != 0) {
        rawstd_error("zfs: create failed for dataset %s\n", dataset.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::string path = device_path(id);
    res = wait_for_device(path);
    if (res != 0) {
        rawstd_error("zfs: device %s did not appear\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb(0);
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::string dataset = _parent_dataset + "/" + uuid_str;

    rawstd_info("zfs: destroying zvol %s\n", dataset.c_str());

    const char* argv[] = {"zfs", "destroy", dataset.c_str(), nullptr};

    int res = run_command(argv);
    if (res != 0) {
        rawstd_error("zfs: destroy failed for dataset %s\n", dataset.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb(0);
}

} // namespace zfs
} // namespace rawstor
