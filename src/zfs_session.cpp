#include "zfs_session.hpp"

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

std::string parse_parent_dataset(const rawstd::URI& location) {
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
    // Strip leading slash: /tank/rawstor -> tank/rawstor.
    if (path.front() == '/') {
        path = path.substr(1);
    }
    return path;
}

} // namespace

namespace rawstor {
namespace zfs {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Session(p, queue, location),
    _parent_dataset(parse_parent_dataset(location)) {
}

std::string Session::_device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << "/dev/zvol/" << _parent_dataset << "/" << uuid_str;
    return oss.str();
}

rawstd::Task<int> Session::_connect(const RawstdUUID& id) {
    std::string path = _device_path(id);

    rawstd_info("Connecting to %s...\n", path.c_str());
    // No O_NONBLOCK: opening a ZFS zvol with it caused cache-miss reads to
    // return -EAGAIN, which io_uring could not properly handle for
    // buffered block device I/O, resulting in -EPROTO propagated to the
    // caller -- io_uring handles blocking operations internally via its
    // io_wq worker threads and does not need the fd to be non-blocking.
    // O_CLOEXEC so this fd doesn't leak into the zfs create/destroy
    // children forked by create()/remove() below.
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

    auto [error, output] = rawstor::run_command_capture(
        {"zfs", "list", "-H", "-o", "name", "-r", _parent_dataset}
    );
    if (error != 0) {
        rawstd_error(
            "zfs: failed to list volumes under %s\n", _parent_dataset.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    std::string prefix = _parent_dataset + "/";

    std::istringstream iss(output);
    std::string line;
    while (std::getline(iss, line)) {
        if (line.compare(0, prefix.size(), prefix) != 0) {
            continue;
        }
        std::string name = line.substr(prefix.size());
        if (name.find('/') != std::string::npos) {
            continue; // Not a direct child of the parent dataset.
        }

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
    // zfs-create(8) rejects volume sizes that are not a multiple of
    // volblocksize (16 KiB by default, 8 KiB on older OpenZFS), so round
    // the requested size up front.
    const uint64_t volblocksize = 16384;

    if (sp.size == 0 || sp.size > UINT64_MAX - (volblocksize - 1)) {
        rawstd_error("zfs: invalid object size: %" PRIu64 "\n", sp.size);
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
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

    char size_buf[32];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64, size);

    rawstd_info(
        "zfs: creating zvol %s, size %s bytes\n", dataset.c_str(), size_buf
    );

    // GCC 13 ICEs (build_special_member_call) when a std::vector<std::string>
    // argument is brace-initialized directly at the call site of a nested
    // coroutine that's co_await-ed from within another coroutine -- naming
    // the vector first works around it.
    std::vector<std::string> argv = {"zfs", "create", "-V", size_buf, dataset};
    try {
        co_await rawstor::run_command_async(_queue, argv, _device_path(id));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to create zvol %s: %s\n", dataset.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<void> Session::remove(const RawstdUUID& id) {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::string dataset = _parent_dataset + "/" + uuid_str;

    rawstd_info("zfs: destroying zvol %s\n", dataset.c_str());

    std::vector<std::string> argv = {"zfs", "destroy", dataset};
    try {
        co_await rawstor::run_command_async(_queue, argv, "");
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to destroy zvol %s: %s\n", dataset.c_str(), e.what()
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
        {"zfs", "list", "-H", "-p", "-o", "used,available", _parent_dataset}
    );
    if (error != 0) {
        rawstd_error(
            "zfs: failed to query dataset %s\n", _parent_dataset.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    uint64_t used = 0;
    uint64_t available = 0;
    if (sscanf(
            output.c_str(), " %" SCNu64 " %" SCNu64, &used, &available
        ) != 2) {
        rawstd_error(
            "zfs: unexpected zfs-list output for %s\n", _parent_dataset.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    RawstorLocationInfo ret{
        .used = used,
        .total = used + available,
    };

    co_return ret;
}

} // namespace zfs
} // namespace rawstor
