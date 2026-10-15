#include "blk_backend.hpp"

#include "opts.h"

#include <rawio/awaitable.hpp>

#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <unistd.h>

#include <algorithm>
#include <stdexcept>
#include <vector>

#include <cerrno>
#include <cinttypes>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>

#if defined(RAWSTD_ON_LINUX)
#include <linux/falloc.h>
#endif

namespace {

std::string trim(const std::string& s) {
    size_t begin = s.find_first_not_of(" \t\r\n");
    if (begin == std::string::npos) {
        return "";
    }
    size_t end = s.find_last_not_of(" \t\r\n");
    return s.substr(begin, end - begin + 1);
}

#if defined(RAWSTD_ON_LINUX)
// Either errno a fallocate() mode can fail with when the underlying
// filesystem/backing store just doesn't implement it -- distinct from a
// real failure (e.g. EIO, EINVAL for an out-of-range request), which
// callers below still propagate. ENOSYS is what rawio::poll::Queue's own
// fallocate() (librawio/src/poll_queue.cpp) reports on macOS, which has no
// equivalent syscall at all; EOPNOTSUPP is what Linux itself reports for a
// mode a given filesystem doesn't support.
bool fallocate_not_supported(int error) noexcept {
    return error == EOPNOTSUPP || error == ENOSYS;
}
#endif

} // namespace

namespace rawstor {
namespace blk {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Backend(p, queue, location),
    _writes_in_flight(0),
    _next_ticket(0),
    _pending_writes_bytes(0) {
}

rawstd::Task<void> Backend::leave() {
    co_return;
}

rawstd::Task<void> Backend::_throttle_acquire(size_t size) {
    unsigned int limit = rawstor_opts_write_throttle_limit();

    if (_writes_in_flight >= limit) {
        // Recv/whatever else feeds writes into this Backend keeps running
        // regardless of this suspension, so nothing else caps how much an
        // already-throttled caller could pile up waiting -- reject
        // outright once queuing this one would push the backlog over the
        // cap, rather than let it grow without bound while storage
        // catches up.
        if (_pending_writes_bytes + size >
            rawstor_opts_write_backlog_capacity()) {
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }

        _pending_writes_bytes += size;
        unsigned int ticket = _next_ticket++;
        co_await _release_barrier.at_least(ticket - limit + 1);
        _pending_writes_bytes -= size;
    } else {
        ++_next_ticket;
    }

    ++_writes_in_flight;
}

void Backend::_throttle_release() noexcept {
    --_writes_in_flight;
    _release_barrier.advance();
}

rawstd::Task<void> Backend::_connect() {
    // The fd is opened lazily, by _open_object()/_open_version(), once
    // set_object()/set_version() knows which object id to open --
    // nothing to do upfront.
    co_return;
}

rawstd::Task<int>
Backend::_open_version(const RawstdUUID&, uint64_t, const RawstdUUID&) {
    RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
}

rawstd::Task<void>
Backend::_zero_fill(int target_fd, uint64_t offset, size_t size, bool unmap) {
#if defined(RAWSTD_ON_LINUX)
    // FALLOC_FL_PUNCH_HOLE additionally deallocates the range (what
    // `unmap` asks for) while still guaranteeing zero readback, same as
    // FALLOC_FL_ZERO_RANGE alone -- see fallocate(2).
    int mode = unmap ? (FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE)
                     : FALLOC_FL_ZERO_RANGE;
    try {
        co_await _queue.fallocate(
            target_fd, mode, static_cast<off_t>(offset),
            static_cast<off_t>(size)
        );
        co_return;
    } catch (const std::system_error& e) {
        if (!fallocate_not_supported(e.code().value())) {
            throw;
        }
        // Falls through to the portable zero-fill path below.
        rawstd_warning(
            "fd %d: fallocate() zero-range not supported by this backing "
            "store -- falling back to an explicit zero-fill write loop "
            "(size = %zu, much slower)\n",
            target_fd, size
        );
    }
#else
    (void)unmap;
#endif

    static constexpr size_t chunk_size = 1u << 20; // 1MB
    std::vector<unsigned char> zeros(std::min(size, chunk_size), 0);
    size_t remaining = size;
    off_t at = static_cast<off_t>(offset);
    while (remaining > 0) {
        size_t chunk = std::min(remaining, zeros.size());
        co_await _queue.pwrite(target_fd, zeros.data(), chunk, at, false);
        remaining -= chunk;
        at += static_cast<off_t>(chunk);
    }
}

rawstd::Task<bool> Backend::_exists(const std::string& path) {
    struct stat st;
    try {
        co_await _queue.stat(path.c_str(), &st);
    } catch (const std::system_error& e) {
        if (e.code().value() == ENOENT) {
            co_return false;
        }
        throw;
    }
    co_return true;
}

rawstd::Task<void> Backend::close() {
    int f = fd();
    if (f == -1) {
        co_return;
    }
    set_fd(-1);
    co_await _queue.close(f);
}

rawstd::Task<void>
Backend::set_object(const RawstdUUID& id, uint64_t offset, int flags) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }
    co_await _bind_object(id, offset, flags, RawstdUUID{});
}

rawstd::Task<void> Backend::set_state(
    const RawstdUUID& id, uint64_t offset, RawstorObjectSyncStateValue expected,
    RawstorObjectSyncStateValue state
) {
    RawstorObjectMeta meta =
        (co_await this->meta(id, offset, RawstdUUID{})).front();
    if (meta.state == expected) {
        meta.state = state;
        co_await _write_meta(
            id, offset, meta.state, meta.config, meta.promised, meta.accepted
        );
    }
}

rawstd::Task<void> Backend::set_config(
    const RawstdUUID& id, uint64_t offset, uint8_t,
    const RawstorObjectConfig& config, unsigned int flags,
    std::optional<RawstorObjectSyncStateValue> state
) {
    _validate_config_update(flags, state);
    for (size_t i = 0; i < config.nroles; ++i) {
        if (config.roles[i] > RAWSTOR_OBJECT_MEMBER_EXCLUDED) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }
    }
    RawstorObjectMeta meta{};
    meta.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
    try {
        meta = (co_await this->meta(id, offset, RawstdUUID{})).front();
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }
    meta.config = config;
    if (state) {
        meta.state = *state;
    }
    co_await _write_meta(
        id, offset, meta.state, meta.config, meta.promised, meta.accepted
    );
}

rawstd::Task<RawstorObjectSyncReply> Backend::sync_prepare(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot&,
    const RawstorObjectSyncReply& proposed
) {
    if (proposed.ok) {
        co_await _write_meta(
            id, offset, proposed.meta.state, proposed.meta.config,
            proposed.meta.promised, proposed.meta.accepted
        );
    }
    co_return proposed;
}

rawstd::Task<RawstorObjectSyncReply> Backend::sync_accept(
    const RawstdUUID& id, uint64_t offset, uint8_t, const RawstorObjectBallot&,
    const RawstorObjectBallot&, const RawstorObjectConfig&,
    const RawstorObjectSyncReply& proposed
) {
    if (proposed.ok) {
        co_await _write_meta(
            id, offset, proposed.meta.state, proposed.meta.config,
            proposed.meta.promised, proposed.meta.accepted
        );
    }
    co_return proposed;
}

rawstd::Task<void> Backend::set_version(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    co_await _bind_object(id, offset, RAWSTOR_READONLY, version_id);
}

rawstd::Task<void> Backend::_bind_object(
    const RawstdUUID& id, uint64_t offset, int flags,
    const RawstdUUID& version_id
) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }
    auto records = co_await meta(id, offset, version_id);
    if (records.size() != 1) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }
    const auto& record = records.front();
    if (record.member_role == RAWSTOR_MEMBER_WITNESS) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }
    int opened = rawstd_uuid_is_nil(&version_id)
                     ? co_await _open_object(id, offset, flags)
                     : co_await _open_version(id, offset, version_id);
    set_fd(opened);
}

std::string Backend::meta_encode(
    RawstorObjectSyncStateValue state, const RawstorObjectConfig& config,
    const RawstorObjectBallot& promised, const RawstorObjectBallot& accepted,
    const ChunkIdentity& identity
) {
    const RawstorObjectConfig& c = config;
    std::string roles;
    if (c.nroles == 0) {
        roles = "-";
    }
    for (uint8_t i = 0; i < c.nroles; ++i) {
        roles += static_cast<char>('0' + (c.roles[i] & 0x7));
    }

    char buf[META_MAX_SIZE];
    int n = snprintf(
        buf, sizeof(buf),
        "version=%u:state=%u:epoch=%" PRIx64 ":sync_id=%" PRIx64 ":h0=%" PRIx64
        ":h1=%" PRIx64 ":h2=%" PRIx64 ":h3=%" PRIx64 ":resync_owner=%" PRIx64
        ":promised=%" PRIx64 ".%" PRIx64 ":accepted=%" PRIx64 ".%" PRIx64
        ":roles=%s:member_role=%u:width=%u:chunk_size=%" PRIx64
        ":size=%" PRIx64,
        META_FORMAT_VERSION, (unsigned int)state, c.epoch, c.sync_id,
        c.sync_id_history[0], c.sync_id_history[1], c.sync_id_history[2],
        c.sync_id_history[3], c.resync_owner, promised.counter,
        promised.proposer, accepted.counter, accepted.proposer, roles.c_str(),
        (unsigned int)identity.member_role, (unsigned int)identity.width,
        identity.chunk_size, identity.size
    );
    if (n < 0 || static_cast<size_t>(n) >= sizeof(buf)) {
        RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
    }
    return std::string(buf, static_cast<size_t>(n));
}

void Backend::meta_decode(
    const std::string& value, RawstorObjectSyncStateValue* state,
    RawstorObjectConfig* config, RawstorObjectBallot* promised,
    RawstorObjectBallot* accepted, ChunkIdentity* identity
) {
    *state = RawstorObjectSyncStateValue{};
    *config = RawstorObjectConfig{};
    *promised = RawstorObjectBallot{};
    *accepted = RawstorObjectBallot{};
    *identity = ChunkIdentity{};
    RawstorObjectConfig& c = *config;
    unsigned int version = 0;
    unsigned int parsed_state = 0;
    unsigned int member_role = 0;
    unsigned int width = 0;
    char roles[RAWSTOR_OBJECT_MAX_WIDTH + 2] = {};
    int consumed = 0;

    std::string v = trim(value);
    int n = sscanf(
        v.c_str(),
        "version=%u:state=%u:epoch=%" SCNx64 ":sync_id=%" SCNx64 ":h0=%" SCNx64
        ":h1=%" SCNx64 ":h2=%" SCNx64 ":h3=%" SCNx64 ":resync_owner=%" SCNx64
        ":promised=%" SCNx64 ".%" SCNx64 ":accepted=%" SCNx64 ".%" SCNx64
        ":roles=%256[0-9-]:member_role=%u:width=%u:chunk_size=%" SCNx64
        ":size=%" SCNx64 "%n",
        &version, &parsed_state, &c.epoch, &c.sync_id, &c.sync_id_history[0],
        &c.sync_id_history[1], &c.sync_id_history[2], &c.sync_id_history[3],
        &c.resync_owner, &(*promised).counter, &(*promised).proposer,
        &(*accepted).counter, &(*accepted).proposer, roles, &member_role,
        &width, &identity->chunk_size, &identity->size, &consumed
    );
    if (n != 18 || static_cast<size_t>(consumed) != v.size() ||
        version != META_FORMAT_VERSION || width == 0 || width > UINT8_MAX ||
        (member_role != RAWSTOR_MEMBER_DATA &&
         member_role != RAWSTOR_MEMBER_WITNESS)) {
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    size_t nroles = 0;
    if (strcmp(roles, "-") != 0) {
        nroles = strlen(roles);
        if (nroles > RAWSTOR_OBJECT_MAX_WIDTH) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        for (size_t i = 0; i < nroles; ++i) {
            if (roles[i] < '0' || roles[i] > '9') {
                RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
            }
            c.roles[i] = static_cast<uint8_t>(roles[i] - '0');
        }
    }
    c.nroles = static_cast<uint8_t>(nroles);
    *state = static_cast<RawstorObjectSyncStateValue>(parsed_state);
    identity->member_role = static_cast<RawstorMemberRole>(member_role);
    identity->width = static_cast<uint8_t>(width);
}

rawstd::Task<size_t> Backend::pread(void* buf, size_t size, uint64_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 "\n", __FUNCTION__, fd(),
        size, offset
    );

    co_return co_await _queue.pread(
        fd(), buf, size, static_cast<off_t>(offset)
    );
}

rawstd::Task<size_t>
Backend::preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 "\n", __FUNCTION__, fd(),
        size, offset
    );

    co_return co_await _queue.preadv(
        fd(), iov, niov, static_cast<off_t>(offset)
    );
}

rawstd::Task<size_t> Backend::pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t
) {

    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 ", sync = %d\n",
        __FUNCTION__, fd(), size, offset, sync
    );

    co_await _throttle_acquire(size);
    size_t result;
    try {
        result = co_await _queue.pwrite(
            fd(), buf, size, static_cast<off_t>(offset), sync
        );
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return result;
}

rawstd::Task<size_t> Backend::resync_pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
) {
    co_return co_await pwrite(buf, size, offset, sync, epoch);
}

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
    bool sync, uint64_t epoch
) {
    (void)epoch;
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 ", sync = %d\n",
        __FUNCTION__, fd(), size, offset, sync
    );

    co_await _throttle_acquire(size);
    size_t result;
    try {
        result = co_await _queue.pwritev(
            fd(), iov, niov, static_cast<off_t>(offset), sync
        );
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return result;
}

rawstd::Task<size_t> Backend::discard(size_t size, uint64_t offset, uint64_t) {

    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 "\n", __FUNCTION__, fd(),
        size, offset
    );

#if defined(RAWSTD_ON_LINUX)
    try {
        co_await _queue.fallocate(
            fd(), FALLOC_FL_PUNCH_HOLE | FALLOC_FL_KEEP_SIZE,
            static_cast<off_t>(offset), static_cast<off_t>(size)
        );
    } catch (const std::system_error& e) {
        // discard() is purely advisory (see its own doc comment on
        // rawstor::Backend) -- a backing store that can't reclaim the
        // range just means nothing was reclaimed, not that the call
        // failed.
        if (!fallocate_not_supported(e.code().value())) {
            throw;
        }
    }
#endif

    co_return size;
}

rawstd::Task<size_t> Backend::write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t
) {

    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64
        ", unmap = %d, sync = %d\n",
        __FUNCTION__, fd(), size, offset, unmap, sync
    );

    co_await _throttle_acquire(size);
    try {
        co_await _zero_fill(fd(), offset, size, unmap);

        // Neither fallocate() (metadata + any data it touches) nor the
        // zero-fill loop above (each individual pwrite() issued with
        // sync=false, since there's no point paying for a durable write
        // per chunk when one fsync() covers the whole range at the end)
        // has a per-call durability flag the way pwrite()'s own RWF_DSYNC
        // does -- a single fdatasync() after the fact is this function's
        // only way to honor `sync`.
        if (sync) {
            co_await _queue.fsync(fd(), /*datasync=*/true);
        }
    } catch (...) {
        _throttle_release();
        throw;
    }
    _throttle_release();

    co_return size;
}

rawstd::Task<size_t> Backend::resync_write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
) {
    co_return co_await write_zeroes(size, offset, unmap, sync, epoch);
}

rawstd::Task<void> Backend::flush(uint64_t) {

    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    co_await _queue.fsync(fd(), /*datasync=*/true);
}

} // namespace blk
} // namespace rawstor
