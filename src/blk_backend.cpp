#include "blk_backend.hpp"

#include "config_wire.hpp"
#include "opts.h"

#include <rawio/awaitable.hpp>

#include <rawstd/caspaxos.hpp>
#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <sys/ioctl.h>
#include <sys/stat.h>

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
#include <linux/fs.h>
#endif

namespace {

// The record `meta` holds, with `state` in place of its own.
rawstor::blk::Backend::Record
record_of(const RawstorObjectMeta& meta, RawstorObjectSyncStateValue state) {
    return rawstor::blk::Backend::Record{
        state, meta.config, meta.promised, meta.accepted
    };
}

rawstd::caspaxos::Ballot ballot_from(const RawstorObjectBallot& b) noexcept {
    return rawstd::caspaxos::Ballot{b.counter, b.proposer};
}

RawstorObjectBallot ballot_to(const rawstd::caspaxos::Ballot& b) noexcept {
    return RawstorObjectBallot{b.counter, b.proposer};
}

// Releases a member's record lock on every way out of a coroutine.
struct RecordLockGuard {
    rawstor::LocalMember& member;
    ~RecordLockGuard() { member.record.unlock(); }
};

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
    _pending_writes_bytes(0),
    _member_id{},
    _member_offset(0),
    _wrote(false),
    _left(false) {
}

Backend::~Backend() {
    // Torn down without close(): the session still leaves the count, but
    // nothing can be written to the record from here.
    if (_member) {
        --_member->writers;
    }
}

rawstd::Task<void> Backend::_mark_dirty() {
    while (_dirty_gate.running()) {
        co_await _dirty_gate.settle();
        if (_member->dirty.load(std::memory_order_acquire)) {
            co_return;
        }
    }
    _dirty_gate.begin();
    struct GateEnd {
        rawstd::Gate& gate;
        ~GateEnd() { gate.end(); }
    } gate_end{_dirty_gate};

    co_await _member->record.lock(_queue);
    RecordLockGuard guard{*_member};

    if (_member->dirty.load(std::memory_order_acquire)) {
        co_return;
    }
    RawstorObjectMeta meta =
        (co_await _meta(_member_id, _member_offset, RawstdUUID{})).front();
    if (meta.state == RAWSTOR_OBJECT_SYNC_STATE_CLEAN) {
        co_await _write_record(
            _member_id, _member_offset,
            record_of(meta, RAWSTOR_OBJECT_SYNC_STATE_DIRTY)
        );
    }
    _member->dirty.store(true, std::memory_order_release);
}

rawstd::Task<void> Backend::_depart() {
    std::shared_ptr<LocalMember> member = std::move(_member);
    co_await member->record.lock(_queue);
    RecordLockGuard guard{*member};

    uint32_t remaining = --member->writers;
    if (!(_left ? remaining == 0 : _wrote)) {
        co_return;
    }
    RawstorObjectMeta meta =
        (co_await _meta(_member_id, _member_offset, RawstdUUID{})).front();
    if (meta.state != RAWSTOR_OBJECT_SYNC_STATE_DIRTY) {
        co_return;
    }
    if (_left) {
        co_await _write_record(
            _member_id, _member_offset,
            record_of(meta, RAWSTOR_OBJECT_SYNC_STATE_CLEAN)
        );
        member->dirty.store(false, std::memory_order_release);
    } else {
        rawstd_warning(
            "%s: a writer left without closing; the copy is LOST\n",
            str().c_str()
        );
        co_await _write_record(
            _member_id, _member_offset,
            record_of(meta, RAWSTOR_OBJECT_SYNC_STATE_LOST)
        );
    }
}

rawstd::Task<void> Backend::leave() {
    _left = true;
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
    if (_member) {
        try {
            co_await _depart();
        } catch (const std::exception& e) {
            rawstd_error("%s: %s\n", str().c_str(), e.what());
        }
    }

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

    int fd = co_await _open_object(id, offset, flags);
    set_fd(fd);

    if ((flags & RAWSTOR_READONLY) == 0) {
        std::shared_ptr<LocalMember> member =
            local_member(location(), id, offset);
        co_await member->record.lock(_queue);
        RecordLockGuard guard{*member};
        ++member->writers;
        // A volume without a record yet has no configuration to fence by.
        try {
            member->learn_epoch(
                (co_await _meta(id, offset, RawstdUUID{})).front().config.epoch
            );
        } catch (const std::system_error&) {
        }
        _member = std::move(member);
        _member_id = id;
        _member_offset = offset;
    }
}

rawstd::Task<void> Backend::set_config(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectConfig& config,
    unsigned int flags, uint8_t position
) {
    std::shared_ptr<LocalMember> member = local_member(location(), id, offset);
    co_await member->record.lock(_queue);
    RecordLockGuard guard{*member};
    co_await member->raise_epoch(_queue, config.epoch);

    // The copy keeps its own state. A volume without a record yet (F10)
    // starts CLEAN: nothing was written to it under one.
    Record record{RAWSTOR_OBJECT_SYNC_STATE_CLEAN, config, {}, {}};
    try {
        RawstorObjectMeta current =
            (co_await _meta(id, offset, RawstdUUID{})).front();
        record = record_of(current, current.state);
        record.config = config;
    } catch (const std::system_error&) {
    }
    if ((flags & RAWSTOR_CONFIG_CLEAR_LOST) != 0 &&
        record.state == RAWSTOR_OBJECT_SYNC_STATE_LOST) {
        record.state = member->writers.load() == 0
                           ? RAWSTOR_OBJECT_SYNC_STATE_CLEAN
                           : RAWSTOR_OBJECT_SYNC_STATE_DIRTY;
    }
    co_await _write_record(id, offset, record);
    member->follow_role(role_of(config, position));
    member->dirty.store(
        record.state != RAWSTOR_OBJECT_SYNC_STATE_CLEAN,
        std::memory_order_release
    );
}

rawstd::Task<Backend::SyncReply> Backend::sync_prepare(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot& ballot
) {
    std::shared_ptr<LocalMember> member = local_member(location(), id, offset);
    co_await member->record.lock(_queue);
    RecordLockGuard guard{*member};

    RawstorObjectMeta meta = (co_await _meta(id, offset, RawstdUUID{})).front();
    rawstd::caspaxos::AcceptorState<RawstorObjectConfig> state{
        ballot_from(meta.promised), ballot_from(meta.accepted), meta.config
    };
    bool ok = rawstd::caspaxos::prepare(state, ballot_from(ballot));
    if (ok) {
        meta.promised = ballot_to(state.promised);
        co_await _write_record(id, offset, record_of(meta, meta.state));
    }
    meta.writers = member->writers.load();
    co_return SyncReply{ok, meta};
}

rawstd::Task<Backend::SyncReply> Backend::sync_accept(
    const RawstdUUID& id, uint64_t offset, const RawstorObjectBallot& ballot,
    const RawstorObjectBallot& next, const RawstorObjectConfig& config,
    unsigned int flags, uint32_t sessions, uint8_t position
) {
    std::shared_ptr<LocalMember> member = local_member(location(), id, offset);
    co_await member->record.lock(_queue);
    RecordLockGuard guard{*member};

    RawstorObjectMeta meta{};
    rawstd::caspaxos::AcceptorState<RawstorObjectConfig> state{};
    bool ok = false;
    // Decided on the record as it is once the epoch is raised: raising may
    // let go of the record meanwhile (LocalMember::raise_epoch()).
    for (bool again = true; again;) {
        meta = (co_await _meta(id, offset, RawstdUUID{})).front();
        // Deciding alone on two members is safe only while no other writer
        // is known to the copy: one with a session open, or one that
        // dropped its session and may be deciding alone on the other
        // member right now.
        if ((flags & RAWSTOR_SYNC_ALONE) != 0 &&
            (member->writers.load() > sessions ||
             meta.state == RAWSTOR_OBJECT_SYNC_STATE_LOST)) {
            RAWSTD_THROW_SYSTEM_ERROR(EBUSY);
        }
        state = {
            ballot_from(meta.promised), ballot_from(meta.accepted), meta.config
        };
        ok = rawstd::caspaxos::accept(
            state, ballot_from(ballot), config, ballot_from(next)
        );
        again = ok && co_await member->raise_epoch(_queue, config.epoch);
    }
    if (ok) {
        meta.promised = ballot_to(state.promised);
        meta.accepted = ballot_to(state.accepted);
        meta.config = state.value;
        co_await _write_record(id, offset, record_of(meta, meta.state));
        member->follow_role(role_of(meta.config, position));
    }
    meta.writers = member->writers.load();
    co_return SyncReply{ok, meta};
}

rawstd::Task<std::vector<RawstorObjectMeta>> Backend::meta(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    std::vector<RawstorObjectMeta> metas =
        co_await _meta(id, offset, version_id);
    if (rawstd_uuid_is_nil(&version_id)) {
        uint32_t writers = local_member(location(), id, offset)->writers.load();
        for (RawstorObjectMeta& m : metas) {
            m.writers = writers;
        }
    }
    co_return metas;
}

rawstd::Task<void> Backend::set_version(
    const RawstdUUID& object_id, uint64_t offset, const RawstdUUID& version_id
) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = co_await _open_version(object_id, offset, version_id);
    set_fd(fd);
}

rawstd::Task<uint64_t> Backend::_blk_size(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
#if defined(RAWSTD_ON_LINUX)
    int f = rawstd_uuid_is_nil(&version_id)
                ? co_await _open_object(id, offset, 0)
                : co_await _open_version(id, offset, version_id);

    uint64_t size = 0;
    if (ioctl(f, BLKGETSIZE64, &size) == -1) {
        int error = errno;
        ::close(f);
        errno = error;
        RAWSTD_THROW_ERRNO();
    }

    co_await _queue.close(f);
    co_return size;
#else
    (void)id;
    (void)offset;
    (void)version_id;
    RAWSTD_THROW_SYSTEM_ERROR(ENOSYS);
#endif
}

std::string
Backend::meta_encode(const Record& record, const ChunkIdentity& identity) {
    const RawstorObjectConfig& c = record.config;
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
        ":roles=%s:member_role=%u:width=%u:chunk_size=%" PRIx64,
        META_FORMAT_VERSION, (unsigned int)record.state, c.epoch, c.sync_id,
        c.sync_id_history[0], c.sync_id_history[1], c.sync_id_history[2],
        c.sync_id_history[3], c.resync_owner, record.promised.counter,
        record.promised.proposer, record.accepted.counter,
        record.accepted.proposer, roles.c_str(),
        (unsigned int)identity.member_role, (unsigned int)identity.width,
        identity.chunk_size
    );
    if (n < 0 || static_cast<size_t>(n) >= sizeof(buf)) {
        RAWSTD_THROW_SYSTEM_ERROR(EOVERFLOW);
    }
    return std::string(buf, static_cast<size_t>(n));
}

void Backend::meta_decode(
    const std::string& value, Record* record, ChunkIdentity* identity
) {
    *record = Record{};
    *identity = ChunkIdentity{};
    RawstorObjectConfig& c = record->config;
    unsigned int version = 0;
    unsigned int state = 0;
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
        ":roles=%256[0-9-]:member_role=%u:width=%u:chunk_size=%" SCNx64 "%n",
        &version, &state, &c.epoch, &c.sync_id, &c.sync_id_history[0],
        &c.sync_id_history[1], &c.sync_id_history[2], &c.sync_id_history[3],
        &c.resync_owner, &record->promised.counter, &record->promised.proposer,
        &record->accepted.counter, &record->accepted.proposer, roles,
        &member_role, &width, &identity->chunk_size, &consumed
    );
    if (n != 17 || static_cast<size_t>(consumed) != v.size() ||
        version != META_FORMAT_VERSION) {
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
    record->state = static_cast<RawstorObjectSyncStateValue>(state);
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

rawstd::Task<size_t>
Backend::pwrite(const void* buf, size_t size, uint64_t offset, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 ", sync = %d\n",
        __FUNCTION__, fd(), size, offset, sync
    );

    _wrote = true;
    co_await _throttle_acquire(size);
    size_t result;
    try {
        // Marked in throttle order: the first write through marks the
        // copy, the rest find it marked.
        if (_member && !_member->dirty.load(std::memory_order_acquire)) {
            co_await _mark_dirty();
        }
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

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset, bool sync
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64 ", sync = %d\n",
        __FUNCTION__, fd(), size, offset, sync
    );

    _wrote = true;
    co_await _throttle_acquire(size);
    size_t result;
    try {
        // Marked in throttle order: the first write through marks the
        // copy, the rest find it marked.
        if (_member && !_member->dirty.load(std::memory_order_acquire)) {
            co_await _mark_dirty();
        }
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

rawstd::Task<size_t> Backend::discard(size_t size, uint64_t offset) {
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

rawstd::Task<size_t>
Backend::write_zeroes(size_t size, uint64_t offset, bool unmap, bool sync) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %" PRIu64
        ", unmap = %d, sync = %d\n",
        __FUNCTION__, fd(), size, offset, unmap, sync
    );

    _wrote = true;
    co_await _throttle_acquire(size);
    try {
        // Marked in throttle order: the first write through marks the
        // copy, the rest find it marked.
        if (_member && !_member->dirty.load(std::memory_order_acquire)) {
            co_await _mark_dirty();
        }
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

rawstd::Task<void> Backend::flush() {
    rawstd_debug("%s(): fd = %d\n", __FUNCTION__, fd());

    co_await _queue.fsync(fd(), /*datasync=*/true);
}

} // namespace blk
} // namespace rawstor
