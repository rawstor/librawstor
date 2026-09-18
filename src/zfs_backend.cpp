#include "zfs_backend.hpp"

#include "location.hpp"
#include "opts.h"
#include "subprocess.hpp"
#include "target.hpp"

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
#include <cstdlib>
#include <cstring>
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

std::string Backend::_dataset(
    const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << _parent_dataset << "/" << uuid_str;
    if (chunk_offset != 0) {
        oss << ":" << chunk_offset;
    }
    if (!rawstd_uuid_is_nil(&snap_id)) {
        RawstdUUIDString snap_str;
        rawstd_uuid_to_string(&snap_id, &snap_str);
        oss << "@s" << snap_str;
    }
    return oss.str();
}

std::string Backend::_device_path(
    const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << "/dev/zvol/" << _parent_dataset << "/" << uuid_str;
    if (chunk_offset != 0) {
        oss << ":" << chunk_offset;
    }
    if (!rawstd_uuid_is_nil(&snap_id)) {
        RawstdUUIDString snap_str;
        rawstd_uuid_to_string(&snap_id, &snap_str);
        oss << "@s" << snap_str;
    }
    return oss.str();
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

rawstd::Task<int> Backend::_open(
    const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
) {
    std::string path = _device_path(id, chunk_offset, snap_id);

    // No O_NONBLOCK: opening a ZFS zvol with it caused cache-miss reads to
    // return -EAGAIN, which io_uring could not properly handle for
    // buffered block device I/O, resulting in -EPROTO propagated to the
    // caller -- io_uring handles blocking operations internally via its
    // io_wq worker threads and does not need the fd to be non-blocking.
    // O_CLOEXEC so this fd doesn't leak into the zfs create/destroy
    // children forked by create()/remove() below. A snapshot device is
    // read-only at the device level too (docs/mds.md,
    // "Snapshots") -- O_RDONLY here, not O_RDWR, so a write against one
    // fails as soon as the fd itself is wrong, before ever reaching
    // pwrite().
    int fd = co_await _queue.open(
        path.c_str(),
        (rawstd_uuid_is_nil(&snap_id) ? O_RDWR : O_RDONLY) | O_CLOEXEC, 0
    );
    co_return fd;
}

rawstd::Task<void> Backend::list(
    unsigned int limit, std::vector<Target>& targets, ListedObject& token
) {
    ListedObject input_token = token;
    targets.clear();
    token = {};

    std::vector<ListedObject> found;

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

        // A UUID's own string form is always exactly 36 characters
        // (RawstdUUIDString) -- a fixed prefix, since the UUID itself
        // already embeds dashes (8-4-4-4-12), unlike this backend's own
        // ":<chunk_offset>" suffix.
        if (name.size() < 36) {
            continue;
        }
        std::string uuid_part = name.substr(0, 36);
        uint64_t chunk_offset = 0;
        if (name.size() > 36) {
            if (name[36] != ':') {
                continue;
            }
            chunk_offset = strtoull(name.c_str() + 37, nullptr, 10);
        }

        RawstdUUID uuid;
        if (rawstd_uuid_from_string(&uuid, uuid_part.c_str()) < 0) {
            continue;
        }
        found.push_back(ListedObject{uuid, chunk_offset, RawstdUUID{}});
    }

    std::sort(found.begin(), found.end());

    found.erase(
        found.begin(), std::upper_bound(found.begin(), found.end(), input_token)
    );

    if (limit == 0) {
        limit = rawstor_opts_list_limit();
    } else {
        limit = std::min(limit, rawstor_opts_list_limit());
    }

    bool capped = found.size() > limit;
    if (capped) {
        found.resize(limit);
    }

    Location self_location(location().str());
    targets.reserve(found.size());
    for (const ListedObject& obj : found) {
        targets.emplace_back(
            self_location, obj.id, obj.chunk_offset, obj.snap_id
        );
    }
    if (capped) {
        token = found.back();
    }

    co_return;
}

rawstd::Task<void> Backend::create(
    const RawstdUUID& id, uint64_t chunk_offset, const RawstorObjectSpec& sp
) {
    _validate_spec(sp);

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

    std::string device_path = _device_path(id, chunk_offset);

    // create() must behave like open(O_EXCL): retrying it against an id
    // a previous, unacknowledged attempt already fully created needs to
    // fail fast with EEXIST -- already classified as permanent, never
    // retried, by Slot::_with_retry()'s is_permanent_backend_error(),
    // and the same convention file::Backend's own O_EXCL create() already
    // follows -- instead of "zfs create" rejecting an already-existing
    // dataset with a generic, retried-pointlessly EIO.
    if (co_await _exists(device_path)) {
        rawstd_error("zfs: zvol %s already exists\n", device_path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
    }

    std::string dataset = _dataset(id, chunk_offset);

    char size_buf[32];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64, size);

    // A fresh copy starts with sync_id 0: it has never been part of an
    // established sync set (docs/mirroring.md). Setting the property in
    // the same command as creation means there is never a window where
    // the zvol exists without one.
    RawstorObjectSyncState sync_state{};
    sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    Backend::ChunkIdentity identity;
    identity.member_kind = sp.member_kind;
    identity.width = static_cast<uint8_t>(sp.width);
    identity.chunk_size = sp.chunk_size;
    std::string prop =
        std::string(rawstor_property) + "=" + meta_encode(sync_state, identity);

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
        co_await _wait_for_blockdev(
            _device_path(id, chunk_offset), /*want_present=*/true
        );
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to create zvol %s: %s\n", dataset.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<void> Backend::remove(
    const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
) {
    if (!rawstd_uuid_is_nil(&snap_id)) {
        std::string snapshot = _dataset(id, chunk_offset, snap_id);

        rawstd_info("zfs: destroying snapshot %s\n", snapshot.c_str());

        std::vector<std::string> destroy_argv = {"zfs", "destroy", snapshot};
        try {
            co_await rawstor::run_command(_queue, std::move(destroy_argv));
        } catch (const std::system_error& e) {
            rawstd_error(
                "zfs: failed to destroy snapshot %s: %s\n", snapshot.c_str(),
                e.what()
            );
            throw;
        }
        co_return;
    }

    // Matches file::Backend::remove()'s own convention: a nonexistent
    // zvol is ENOENT specifically (permanent -- never retried by
    // Slot::_with_retry()'s is_permanent_backend_error()), not the
    // generic, retryable EIO "zfs destroy" itself would produce for the
    // same case.
    std::string device_path = _device_path(id, chunk_offset);
    if (!co_await _exists(device_path)) {
        rawstd_error("zfs: zvol %s does not exist\n", device_path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    std::string dataset = _dataset(id, chunk_offset);

    rawstd_info("zfs: destroying zvol %s\n", dataset.c_str());

    std::vector<std::string> argv = {"zfs", "destroy", dataset};
    try {
        co_await rawstor::run_command(_queue, std::move(argv));
        co_await _wait_for_blockdev(
            _device_path(id, chunk_offset), /*want_present=*/false
        );
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

rawstd::Task<RawstorObjectMeta>
Backend::meta(const RawstdUUID& id, uint64_t chunk_offset) {
    std::string dataset = _dataset(id, chunk_offset);

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

    // "-" (or an empty value) means the property was never set: a zvol
    // created before this feature, or by something else. Must not be
    // trusted as CLEAN -- the caller treats any error here as "member
    // stale, needs a resync" (docs/mirroring.md, case F10).
    RawstorObjectSyncState sync_state;
    Backend::ChunkIdentity identity;
    try {
        meta_decode(output, &sync_state, &identity);
    } catch (const std::system_error&) {
        rawstd_error("zfs: no recorded mirror state on %s\n", dataset.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    // The property never carries size (see meta_encode()): merge in
    // the zvol's real, current size the same way spec() reports it, rather
    // than trust a value that could go stale if the zvol were ever resized
    // outside rawstor.
    RawstorObjectMeta ret{};
    ret.spec = co_await spec(id, chunk_offset);
    ret.spec.member_kind = identity.member_kind;
    ret.spec.width = identity.width;
    ret.spec.chunk_size = identity.chunk_size;
    ret.sync_state = sync_state;

    co_return ret;
}

rawstd::Task<void> Backend::set_sync_state(
    const RawstdUUID& id, uint64_t chunk_offset,
    const RawstorObjectSyncState& sync_state
) {
    std::string dataset = _dataset(id, chunk_offset);

    // The placement identity is immutable once stamped at create() --
    // read the existing property first and carry it through unchanged
    // rather than clobber it with a zeroed one. A missing/unrecorded
    // property (a zvol created before this feature, or by something
    // else) has no identity to preserve; the fresh one is a standalone
    // (non-chunk) default.
    Backend::ChunkIdentity identity;
    {
        std::vector<std::string> get_argv = {"zfs",  "get",   "-H",
                                             "-o",   "value", rawstor_property,
                                             dataset};
        try {
            std::string output = co_await rawstor::run_command_capture(
                _queue, std::move(get_argv)
            );
            while (!output.empty() &&
                   (output.back() == '\n' || output.back() == '\r')) {
                output.pop_back();
            }
            RawstorObjectSyncState old_sync_state;
            meta_decode(output, &old_sync_state, &identity);
        } catch (const std::system_error&) {
            identity = Backend::ChunkIdentity{};
        }
    }
    std::string prop =
        std::string(rawstor_property) + "=" + meta_encode(sync_state, identity);

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

rawstd::Task<void> Backend::snapshot_create(
    const RawstdUUID& id, uint64_t chunk_offset, const RawstdUUID& snap_id
) {
    if (rawstd_uuid_is_nil(&snap_id)) {
        /* nil is the live version, never a snapshot. */
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::string dataset = _dataset(id, chunk_offset);
    std::string snapshot = _dataset(id, chunk_offset, snap_id);

    rawstd_info("zfs: creating snapshot %s\n", snapshot.c_str());

    // GCC 13 ICEs (build_special_member_call) when a std::vector<std::
    // string> argument is brace-initialized directly at the call site of
    // a nested coroutine that's co_await-ed from within another coroutine
    // -- naming the vector first works around it (see Backend::create()'s
    // own comment on this file).
    std::vector<std::string> snapshot_argv = {"zfs", "snapshot", snapshot};
    try {
        co_await rawstor::run_command(_queue, std::move(snapshot_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to create snapshot %s: %s\n", snapshot.c_str(),
            e.what()
        );
        throw;
    }

    // The snapshot read path opens /dev/zvol/.../<uuid>@s<id>, which
    // exists only with snapdev=visible on the origin. Set it with every
    // snapshot, so every one that exists is also openable -- one
    // mechanism, old zvols included, rather than a per-snapshot property.
    std::vector<std::string> snapdev_argv = {
        "zfs", "set", "snapdev=visible", dataset
    };
    try {
        co_await rawstor::run_command(_queue, std::move(snapdev_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "zfs: failed to set snapdev=visible on %s: %s\n", dataset.c_str(),
            e.what()
        );
        throw;
    }
}

} // namespace zfs
} // namespace rawstor
