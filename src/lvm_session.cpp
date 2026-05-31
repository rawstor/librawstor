#include "lvm_session.hpp"

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
namespace lvm {

static std::string parse_vg_path(const rawstd::URI& location) {
    if (location.scheme() != "lvm") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!location.host().empty()) {
        rawstd_error("Empty host expected: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::string path = location.path().str();
    if (path.empty() || path == "/") {
        rawstd_error("VG path is empty in URI: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return path;
}

static std::string basename_of(const std::string& path) {
    size_t pos = path.rfind('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

Session::Session(rawio::Queue& queue, const rawstd::URI& location) :
    BlkdevSession(queue, location),
    _vg_path(parse_vg_path(location)),
    _vg_name(basename_of(_vg_path)) {
}

std::string Session::device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << _vg_path << "/" << uuid_str;
    return oss.str();
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    char size_arg[64];
    snprintf(size_arg, sizeof(size_arg), "%zub", sp.size);

    rawstd_info(
        "lvm: creating LV %s in VG %s, size %s\n", uuid_str, _vg_name.c_str(),
        size_arg
    );

    const char* argv[] = {"lvcreate", "--yes",          "-L",   size_arg, "-n",
                          uuid_str,   _vg_name.c_str(), nullptr};

    int res = run_command(argv);
    if (res != 0) {
        rawstd_error("lvm: lvcreate failed: %s\n", strerror(-res));
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    std::string path = device_path(id);
    res = wait_for_device(path);
    if (res != 0) {
        rawstd_error("lvm: device %s did not appear\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb(0);
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    std::string path = device_path(id);

    rawstd_info("lvm: removing LV %s\n", path.c_str());

    const char* argv[] = {"lvremove", "-f", path.c_str(), nullptr};

    int res = run_command(argv);
    if (res != 0) {
        rawstd_error("lvm: lvremove failed: %s\n", strerror(-res));
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb(0);
}

} // namespace lvm
} // namespace rawstor
