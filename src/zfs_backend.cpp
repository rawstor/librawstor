#include "zfs_backend.hpp"

#include "blkdev_meta.hpp"
#include "opts.h"
#include "subprocess.hpp"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <sstream>
#include <string>

#include <fcntl.h>

namespace {

const char* const rawstor_property = "rawstor:meta";

std::string parse_parent_dataset(const rawstd::URI& location) {
    if (location.scheme() != "zfs") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (location.host().empty()) {
        rawstd_error("Pool name is empty in URI: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    // location.host() is the pool (a URI host can't itself contain '/');
    // any nested dataset comes back as location.path(), e.g.
    // zfs://tank/rawstor -> host "tank", path "/rawstor".
    return location.host() + location.path().str();
}

} // namespace

namespace rawstor {
namespace zfs {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Backend(p, queue, location),
    _parent_dataset(parse_parent_dataset(location)) {
}

std::string Backend::_device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << "/dev/zvol/" << _parent_dataset << "/" << uuid_str;
    return oss.str();
}

std::string Backend::_dataset(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);
    return _parent_dataset + "/" + uuid_str;
}

rawstd::Task<void> Backend::_wait_for_blockdev(
    const std::string& path, bool want_present, int timeout_ms
) {
    const int interval_ms = 50;

    for (int elapsed = 0; elapsed < timeout_ms; elapsed += interval_ms) {
        struct stat st;
        bool is_blockdev = false;
        try {
            co_await _queue.stat(path.c_str(), &st);
            is_blockdev = S_ISBLK(st.st_mode);
        } catch (const std::system_error&) {
            // Not there -- ENOENT is the expected case, both while
            // waiting for it to appear and once it's finally gone.
        }
        if (is_blockdev == want_present) {
            co_return;
        }
        co_await _queue.timeout(static_cast<unsigned int>(interval_ms) * 1000);
    }

    rawstd_error(
        "Timed out waiting for device %s to %s\n", path.c_str(),
        want_present ? "appear" : "disappear"
    );
    RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
}

rawstd::Task<int> Backend::_open(const RawstdUUID& id) {
    std::string path = _device_path(id);

    // No O_NONBLOCK: opening a ZFS zvol with it caused cache-miss reads to
    // return -EAGAIN, which io_uring could not properly handle for
    // buffered block device I/O, resulting in -EPROTO propagated to the
    // caller -- io_uring handles blocking operations internally via its
    // io_wq worker threads and does not need the fd to be non-blocking.
    // O_CLOEXEC so this fd doesn't leak into the zfs create/destroy
    // children forked by create()/remove() below.
    int fd = co_await _queue.open(path.c_str(), O_RDWR | O_CLOEXEC, 0);
    co_return fd;
}

rawstd::Task<void> Backend::list(
    unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    RawstdUUID input_token = token;
    targets.clear();
    token = {};

    // GCC 13 ICEs (is_this_parameter) when a std::vector<std::string>
    // argument is brace-initialized directly at the call site of a nested
    // coroutine that's co_await-ed from within another coroutine -- naming
    // the vector first works around it.
    std::vector<std::string> list_argv = {"zfs",  "list", "-H",           "-o",
                                          "name", "-r",   _parent_dataset};
    std::string output;
    try {
        output =
            co_await rawstor::run_command_capture(_queue, std::move(list_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to list volumes under %s: %s\n",
            _parent_dataset.c_str(), e.what()
        );
        throw;
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
        targets.begin(), std::upper_bound(
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
Backend::create(const RawstdUUID& id, const RawstorObjectSpec& sp) {
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
    std::string device_path = _device_path(id);

    // create() must behave like open(O_EXCL): retrying it against an id
    // a previous, unacknowledged attempt already fully created needs to
    // fail fast with EEXIST -- already classified as permanent, never
    // retried, by Connection::_with_retry()'s is_permanent_backend_error(),
    // and the same convention file::Backend's own O_EXCL create() already
    // follows -- instead of "zfs create" rejecting an already-existing
    // dataset with a generic, retried-pointlessly EIO.
    if (co_await _exists(device_path)) {
        rawstd_error("zfs: zvol %s already exists\n", device_path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
    }

    std::string dataset = _parent_dataset + "/" + uuid_str;

    char size_buf[32];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64, size);

    // A fresh copy starts with sync_id 0: it has never been part of an
    // established sync set (docs/mirroring.md). Setting the property in
    // the same command as creation means there is never a window where
    // the zvol exists without one.
    RawstorObjectMeta initial{};
    initial.state = RAWSTOR_OBJECT_STATE_CLEAN;
    std::string prop =
        std::string(rawstor_property) + "=" + blkdev_meta_encode(initial);

    rawstd_info(
        "zfs: creating zvol %s, size %s bytes\n", dataset.c_str(), size_buf
    );

    // GCC 13 ICEs (build_special_member_call) when a std::vector<std::string>
    // argument is brace-initialized directly at the call site of a nested
    // coroutine that's co_await-ed from within another coroutine -- naming
    // the vector first works around it.
    std::vector<std::string> argv = {"zfs", "create", "-V",   size_buf,
                                     "-o",  prop,     dataset};
    try {
        co_await rawstor::run_command(_queue, std::move(argv));
        co_await _wait_for_blockdev(_device_path(id), /*want_present=*/true);
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to create zvol %s: %s\n", dataset.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<void> Backend::remove(const RawstdUUID& id) {
    // Matches file::Backend::remove()'s own convention: a nonexistent
    // zvol is ENOENT specifically (permanent -- never retried by
    // Connection::_with_retry()'s is_permanent_backend_error()), not the
    // generic, retryable EIO "zfs destroy" itself would produce for the
    // same case.
    std::string device_path = _device_path(id);
    if (!co_await _exists(device_path)) {
        rawstd_error("zfs: zvol %s does not exist\n", device_path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::string dataset = _parent_dataset + "/" + uuid_str;

    rawstd_info("zfs: destroying zvol %s\n", dataset.c_str());

    std::vector<std::string> argv = {"zfs", "destroy", dataset};
    try {
        co_await rawstor::run_command(_queue, std::move(argv));
        co_await _wait_for_blockdev(_device_path(id), /*want_present=*/false);
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to destroy zvol %s: %s\n", dataset.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<RawstorLocationInfo> Backend::info() {
    // See list()'s own comment on this GCC 13 ICE workaround.
    std::vector<std::string> info_argv = {
        "zfs", "list", "-H", "-p", "-o", "used,available", _parent_dataset
    };
    std::string output;
    try {
        output =
            co_await rawstor::run_command_capture(_queue, std::move(info_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to query dataset %s: %s\n", _parent_dataset.c_str(),
            e.what()
        );
        throw;
    }

    uint64_t used = 0;
    uint64_t available = 0;
    if (sscanf(output.c_str(), " %" SCNu64 " %" SCNu64, &used, &available) !=
        2) {
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

rawstd::Task<RawstorObjectMeta> Backend::meta(const RawstdUUID& id) {
    std::string dataset = _dataset(id);

    std::vector<std::string> argv = {"zfs",  "get",   "-H",
                                     "-o",   "value", rawstor_property,
                                     dataset};
    std::string output;
    try {
        output = co_await rawstor::run_command_capture(_queue, std::move(argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to read mirror state of %s: %s\n", dataset.c_str(),
            e.what()
        );
        throw;
    }

    while (!output.empty() &&
           (output.back() == '\n' || output.back() == '\r')) {
        output.pop_back();
    }

    // "-" means the property was never set: a zvol created before this
    // feature, or by something else. Must not be trusted as CLEAN -- the
    // caller treats any error here as "member stale, needs a resync"
    // (docs/mirroring.md, case F10).
    RawstorObjectMeta meta{};
    if (output.empty() || output == "-" || !blkdev_meta_decode(output, &meta)) {
        rawstd_error("zfs: no recorded mirror state on %s\n", dataset.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    // The property never carries size (see blkdev_meta_encode()): merge in
    // the zvol's real, current size the same way spec() reports it, rather
    // than trust a value that could go stale if the zvol were ever resized
    // outside rawstor.
    RawstorObjectSpec sp = co_await spec(id);
    meta.size = sp.size;

    co_return meta;
}

rawstd::Task<void>
Backend::set_state(const RawstdUUID& id, const RawstorObjectMeta& meta) {
    std::string dataset = _dataset(id);
    std::string prop =
        std::string(rawstor_property) + "=" + blkdev_meta_encode(meta);

    std::vector<std::string> argv = {"zfs", "set", prop, dataset};
    try {
        co_await rawstor::run_command(_queue, std::move(argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to set mirror state on %s: %s\n", dataset.c_str(),
            e.what()
        );
        throw;
    }

    co_return;
}

} // namespace zfs
} // namespace rawstor
