#include "lvm_session.hpp"

#include "opts.h"
#include "subprocess.hpp"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>

#include <fcntl.h>

namespace {

std::string parse_vg_path(const rawstd::URI& location) {
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

std::string basename_of(const std::string& path) {
    size_t pos = path.rfind('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

} // namespace

namespace rawstor {
namespace lvm {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Session(p, queue, location),
    _vg_path(parse_vg_path(location)),
    _vg_name(basename_of(_vg_path)) {
}

std::string Session::_device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << _vg_path << "/" << uuid_str;
    return oss.str();
}

rawstd::Task<int> Session::_connect(const RawstdUUID& id) {
    std::string path = _device_path(id);

    rawstd_info("Connecting to %s...\n", path.c_str());
    // No O_NONBLOCK: io_uring does not need the fd to be non-blocking --
    // it handles blocking operations internally via io_wq worker threads.
    // O_NONBLOCK on a block device instead surfaces cache-miss reads as
    // -EAGAIN, which the pread/pwrite paths above don't retry. O_CLOEXEC
    // so this fd doesn't leak into the lvcreate/lvremove children forked
    // by create()/remove() below.
    int fd = co_await _queue.open(path.c_str(), O_RDWR | O_CLOEXEC, 0);
    rawstd_info("fd %d: Connected\n", fd);
    co_return fd;
}

rawstd::Task<void> Session::list(
    unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    RawstdUUID input_token = token;
    targets.clear();
    token = {};

    auto [error, output] =
        rawstor::run_command_capture({"lvs", "--noheadings", "-o", "lv_name",
                                       "--select", "vg_name=" + _vg_name});
    if (error != 0) {
        rawstd_error("lvm: failed to list LVs in VG %s\n", _vg_name.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        size_t begin = line.find_first_not_of(" \t");
        if (begin == std::string::npos) {
            continue;
        }
        size_t end = line.find_last_not_of(" \t");
        std::string name = line.substr(begin, end - begin + 1);

        RawstdUUID uuid;
        if (rawstd_uuid_from_string(&uuid, name.c_str()) < 0) {
            continue;
        }
        targets.push_back(uuid);
    }

    std::sort(
        targets.begin(), targets.end(),
        [](const RawstdUUID& lhs, const RawstdUUID& rhs) {
            return rawstd_uuid_cmp(&lhs, &rhs) < 0;
        }
    );

    targets.erase(
        targets.begin(),
        std::upper_bound(
            targets.begin(), targets.end(), input_token,
            [](const RawstdUUID& lhs, const RawstdUUID& rhs) {
                return rawstd_uuid_cmp(&lhs, &rhs) < 0;
            }
        )
    );

    if (limit == 0) {
        limit = rawstor_opts_list_limit();
    } else {
        limit = std::min(limit, rawstor_opts_list_limit());
    }

    if (targets.size() > limit) {
        targets.resize(limit);
        token = targets.back();
    }

    co_return;
}

rawstd::Task<void>
Session::create(const RawstdUUID& id, const RawstorObjectSpec& sp) {
    if (sp.size == 0) {
        rawstd_error("lvm: object size must be positive\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    // lvcreate rounds the size up to the VG extent size itself.
    char size_buf[32];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64 "b", sp.size);

    rawstd_info(
        "lvm: creating LV %s in VG %s, size %s\n", uuid_str, _vg_name.c_str(),
        size_buf
    );

    // GCC 13 ICEs (build_special_member_call) when a std::vector<std::string>
    // argument is brace-initialized directly at the call site of a nested
    // coroutine that's co_await-ed from within another coroutine -- naming
    // the vector first works around it.
    std::vector<std::string> argv = {
        "lvcreate", "--yes", "-L", size_buf, "-n", uuid_str, _vg_name
    };
    try {
        co_await rawstor::run_command_async(_queue, argv, _device_path(id));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to create LV %s in VG %s: %s\n", uuid_str,
            _vg_name.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<void> Session::remove(const RawstdUUID& id) {
    std::string path = _device_path(id);

    rawstd_info("lvm: removing LV %s\n", path.c_str());

    std::vector<std::string> argv = {"lvremove", "-f", path};
    try {
        co_await rawstor::run_command_async(_queue, argv, "");
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to remove LV %s: %s\n", path.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<RawstorObjectSpec> Session::spec(const RawstdUUID& id) {
    RawstorObjectSpec ret{
        .size = rawstor::block_device_size(_device_path(id)),
    };

    co_return ret;
}

rawstd::Task<RawstorLocationInfo> Session::info() {
    auto [error, output] = rawstor::run_command_capture(
        {"vgs", "--noheadings", "--units", "b", "--nosuffix", "-o",
         "vg_size,vg_free", _vg_name}
    );
    if (error != 0) {
        rawstd_error("lvm: failed to query VG %s\n", _vg_name.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    uint64_t total = 0;
    uint64_t free_bytes = 0;
    if (sscanf(
            output.c_str(), " %" SCNu64 " %" SCNu64, &total, &free_bytes
        ) != 2) {
        rawstd_error("lvm: unexpected vgs output for VG %s\n", _vg_name.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    RawstorLocationInfo ret{
        .used = total - free_bytes,
        .total = total,
    };

    co_return ret;
}

} // namespace lvm
} // namespace rawstor
