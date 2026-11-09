#include "file_backend.hpp"

#include "opts.h"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <atomic>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <vector>

namespace {

// One chunk's own directory: <location>/<uuid>/<offset>[/<version_id>]
// -- self-describing (docs/mds.md, "Chunk identity"): `uuid` is the
// volume's own id for every one of its chunks, `offset` (0 for a plain object
// or a volume's own chunk 0 -- the two are indistinguishable at this layer by
// design) disambiguates which chunk of that id this is, always its own path
// component (never omitted, unlike the id/offset/version_id path *target
// strings* use -- see TargetPath's own doc comment in target.hpp for why
// those stay optional; a physical directory layout has no such
// ambiguity to worry about, so there's nothing to gain from omitting
// it), and hex, not decimal -- same base as the target URI's own offset
// path segment (parse_target_path()'s own doc comment) and every
// numeric field meta_encode() persists alongside it, so a directory
// listing and its own meta record read the same way. `version_id`, when
// bound, is one directory deeper still: a file:// version is a fake
// snapshot, a full copy of `data` and `meta` made by create_version(). It
// is opened read-only by _open_version() below and described by meta(). Two
// files live directly under a chunk's or a version's directory: `data` (the
// object's own bytes) and `meta` (get_target_meta_path() below).
std::string get_target_dir(
    const std::string& location_path, const RawstdUUIDString& uuid,
    uint64_t offset, const RawstdUUID& version_id = {}
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << "/" << std::hex << offset;
    if (!rawstd_uuid_is_nil(&version_id)) {
        RawstdUUIDString version_string;
        rawstd_uuid_to_string(&version_id, &version_string);
        oss << "/" << version_string;
    }

    return oss.str();
}

std::string get_target_path(
    const std::string& location_path, const RawstdUUIDString& uuid,
    uint64_t offset, const RawstdUUID& version_id = {}
) {
    return get_target_dir(location_path, uuid, offset, version_id) + "/data";
}

std::string get_target_meta_path(
    const std::string& location_path, const RawstdUUIDString& uuid,
    uint64_t offset, const RawstdUUID& version_id = {}
) {
    return get_target_dir(location_path, uuid, offset, version_id) + "/meta";
}

// The versions kept in a chunk's directory: the UUID-named subdirectories
// that hold a `data` file (one still being created has none yet).
std::vector<RawstdUUID> versions_in(const std::string& target_dir) {
    std::vector<RawstdUUID> ret;
    for (const auto& entry : std::filesystem::directory_iterator(target_dir)) {
        if (!entry.is_directory()) {
            continue;
        }
        RawstdUUID version_id;
        if (rawstd_uuid_from_string(
                &version_id, entry.path().filename().string().c_str()
            ) < 0) {
            continue;
        }
        if (!std::filesystem::exists(entry.path() / "data")) {
            continue;
        }
        ret.push_back(version_id);
    }
    return ret;
}

// Creates `path` if it doesn't already exist -- shared by create()'s own
// chain of nested directories (<location>/<uuid>/<offset>), each
// level possibly already made by an earlier chunk of the same id.
void mkdir_or_exist(const std::string& path) {
    if (mkdir(path.c_str(), 0755) == -1) {
        if (errno == EEXIST) {
            errno = 0;
        } else {
            RAWSTD_THROW_ERRNO();
        }
    }
}

std::string get_location_path(const rawstd::URI& location) {
    if (location.scheme() != "file") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!location.host().empty()) {
        rawstd_error("Empty host expected: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return location.path().str();
}

} // unnamed namespace

namespace rawstor {
namespace file {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Backend(p, queue, location) {
}

rawstd::Task<int>
Backend::_open_object(const RawstdUUID& id, uint64_t offset, int flags) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);

    std::string target_path = get_target_path(location_path, id_string, offset);

    // O_CLOEXEC: a file:// backend can be live in the same process as an
    // lvm:// or zfs:// one (Target::open() fans out across every URI of a
    // target concurrently, src/target.cpp), whose create()/remove() shell
    // out via fork()+exec() (src/subprocess.cpp) -- without it, this fd
    // would leak into those children.
    //
    // ENOENT means this one copy is missing from a location that's still
    // there (docs/mirroring.md, case F10) -- Chunk::create() recreates it
    // from a surviving mirror. A location directory that's missing
    // altogether is a different case: the store itself isn't there (e.g.
    // an unmounted disk, whose empty mountpoint is all that's left), so
    // it's reported as unreachable (ENOTCONN) instead, never mistaken for
    // one missing copy to recreate onto whatever filesystem sits
    // underneath.
    bool missing = false;
    int fd = -1;
    try {
        fd = co_await _queue.open(
            target_path.c_str(),
            ((flags & RAWSTOR_READONLY) != 0 ? O_RDONLY : O_RDWR) | O_NONBLOCK |
                O_CLOEXEC,
            0
        );
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
        missing = true;
    }
    if (missing) {
        std::error_code ec;
        if (!std::filesystem::is_directory(location_path, ec)) {
            rawstd_error("Location unavailable: %s\n", location_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
        }
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }
    co_return fd;
}

rawstd::Task<int> Backend::_open_version(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);

    // O_RDONLY: a version is a read-only copy. A missing one is ENOENT
    // (meta() has already answered for it by the time this runs).
    int fd = co_await _queue.open(
        get_target_path(location_path, id_string, offset, version_id).c_str(),
        O_RDONLY | O_NONBLOCK | O_CLOEXEC, 0
    );
    co_return fd;
}

rawstd::Task<void> Backend::list_chunks(
    RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
    RawstdUUID& token, RawstdUUID version_id
) {
    if (!rawstd_uuid_is_nil(&version_id)) {
        // A version is described by meta() only; its chunks are not listed.
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }
    // Filtered by a non-nil `id` (Backend::list_chunks()'s own doc
    // comment): only that one uuid's own offset directories get scanned
    // below, and `token` plays no part.
    bool filtered = !rawstd_uuid_is_nil(&id);
    RawstdUUID input_token = filtered ? RawstdUUID{} : token;
    chunks.clear();
    token = {};
    try {
        std::string location_path = get_location_path(location());

        // Two levels deep: <location>/<uuid>/<offset>/data -- every
        // offset directory under one uuid becomes that uuid's own single
        // ChunkGroup entry (its own offsets sorted ascending).
        // list_chunks() only ever enumerates live objects (docs/mds.md,
        // "Version records are skipped (stage 2)"), so a third,
        // version-named level (get_target_dir()'s own doc comment) never
        // applies here; an offset directory missing its own `data` file
        // (mid-create(), or a leftover empty one after remove()) is
        // silently skipped rather than reported as a malformed name.
        // `offset` is hex, matching get_target_dir()'s own doc comment.
        std::vector<ChunkGroup> found;
        for (const auto& uuid_entry :
             std::filesystem::directory_iterator(location_path)) {
            if (!uuid_entry.is_directory()) {
                continue;
            }
            std::string uuid_name = uuid_entry.path().filename().string();
            RawstdUUID uuid;
            int res = rawstd_uuid_from_string(&uuid, uuid_name.c_str());
            if (res < 0) {
                rawstd_warning(
                    "%s: %s\n", strerror(-res),
                    uuid_entry.path().string().c_str()
                );
                continue;
            }
            if (filtered && rawstd_uuid_cmp(&uuid, &id) != 0) {
                continue;
            }

            std::vector<uint64_t> offsets;
            for (const auto& offset_entry :
                 std::filesystem::directory_iterator(uuid_entry.path())) {
                if (!offset_entry.is_directory()) {
                    continue;
                }
                std::string offset_name = offset_entry.path().filename();
                char* endptr = nullptr;
                errno = 0;
                uint64_t offset = strtoull(offset_name.c_str(), &endptr, 16);
                if (errno != 0 || endptr == offset_name.c_str() ||
                    *endptr != '\0') {
                    errno = 0;
                    continue;
                }
                if (!std::filesystem::exists(offset_entry.path() / "data")) {
                    continue;
                }

                offsets.push_back(offset);
            }
            if (offsets.empty()) {
                continue;
            }

            std::sort(offsets.begin(), offsets.end());
            found.push_back(ChunkGroup{uuid, std::move(offsets)});
        }

        std::sort(
            found.begin(), found.end(),
            [](const ChunkGroup& lhs, const ChunkGroup& rhs) {
                return rawstd_uuid_cmp(&lhs.id, &rhs.id) < 0;
            }
        );

        found.erase(
            found.begin(),
            std::upper_bound(
                found.begin(), found.end(), input_token,
                [](const RawstdUUID& lhs, const ChunkGroup& rhs) {
                    return rawstd_uuid_cmp(&lhs, &rhs.id) < 0;
                }
            )
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

        chunks = std::move(found);
        if (capped) {
            token = chunks.back().id;
        }
    } catch (const std::system_error&) {
        throw;
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    } catch (...) {
        rawstd_error("Unexpected error\n");
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    co_return;
}

rawstd::Task<void> Backend::create(
    const RawstdUUID&, const RawstdUUID& id, uint64_t offset,
    const RawstorObjectSpec& sp, RawstorMemberRole member_role
) {
    std::string location_path = get_location_path(location());
    mkdir_or_exist(location_path);

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);
    mkdir_or_exist(location_path + "/" + uuid_string);

    std::string target_dir = get_target_dir(location_path, uuid_string, offset);
    mkdir_or_exist(target_dir);

    std::string target_path =
        get_target_path(location_path, uuid_string, offset);

    int fd = ::open(
        target_path.c_str(), O_EXCL | O_CREAT | O_WRONLY | O_CLOEXEC,
        S_IRUSR | S_IWUSR
    );
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    std::exception_ptr create_error;
    try {
        // A witness keeps an empty data file for namespace enumeration.
        // Its declared logical size is stored in the companion metadata.
        // Data binding rejects metadata-only members by their role.
        if (member_role != RAWSTOR_MEMBER_WITNESS) {
            // fallocate() actually reserves real blocks -- this file backs a
            // virtio-blk-style virtual disk, so a write into unallocated
            // territory otherwise depends on the filesystem's own delayed
            // allocation, which under ext4's data=ordered journaling must
            // land before the next journal commit. Many concurrent writes
            // into a still-sparse object (a fresh, mostly-unwritten one is
            // the common case) can then back up behind that commit interval
            // -- multiple seconds under sustained load even with the stock
            // 5s commit interval, tens of seconds observed with an
            // unusually long one. Preallocating up front removes writes
            // from that dependency entirely; mode 0 (no FALLOC_FL_KEEP_SIZE)
            // also extends the file to sp.size, so nothing else needs to on
            // that path.
            try {
                co_await _queue.fallocate(
                    fd, 0, 0, static_cast<off_t>(sp.size)
                );
            } catch (const std::system_error& e) {
#if defined(RAWSTD_ON_MACOS)
                if (e.code().value() != ENOSYS) {
                    throw;
                }
                // Queue::fallocate() has no macOS equivalent of Linux's
                // fallocate() to call (see its own doc comment,
                // librawio/include/rawio/queue.hpp) -- F_PREALLOCATE is
                // APFS/HFS+'s, same reasoning as above, but it only reserves
                // the blocks, so ftruncate() still follows to make the file
                // report the requested size. F_ALLOCATECONTIG (contiguous,
                // best-effort) is tried first; falling back to
                // F_ALLOCATEALL (fragmentation allowed) matches the common
                // pattern for this call, since contiguous space this large
                // is often unavailable.
                fstore_t fstore = {
                    .fst_flags = F_ALLOCATECONTIG,
                    .fst_posmode = F_PEOFPOSMODE,
                    .fst_offset = 0,
                    .fst_length = static_cast<off_t>(sp.size),
                };
                if (fcntl(fd, F_PREALLOCATE, &fstore) == -1) {
                    fstore.fst_flags = F_ALLOCATEALL;
                    if (fcntl(fd, F_PREALLOCATE, &fstore) == -1) {
                        RAWSTD_THROW_ERRNO();
                    }
                }
                if (ftruncate(fd, sp.size) == -1) {
                    RAWSTD_THROW_ERRNO();
                }
#else
                throw;
#endif
            }
        }

        co_await _queue.close(fd);
    } catch (...) {
        // co_await is not permitted inside a catch handler -- stash the
        // exception and rethrow it once out of the handler, below, after
        // the cleanup co_awaits.
        create_error = std::current_exception();
    }

    if (create_error) {
        // Best-effort: unlink()/close() failing here must not replace
        // create_error with one of its own.
        try {
            co_await _queue.unlink(target_path.c_str());
        } catch (...) {
        }
        try {
            co_await _queue.close(fd);
        } catch (...) {
        }
        std::rethrow_exception(create_error);
    }

    // A fresh copy starts with sync_id 0: it has never been part of an
    // established sync set (see docs/mirroring.md). Written after the data
    // file so a crash between the two never leaves a meta file without
    // its data file; _write_meta()/meta() failing ENOENT on the reverse
    // (data file present, no meta yet) is exactly case F10.
    std::exception_ptr meta_error;
    try {
        std::string meta_path =
            get_target_meta_path(location_path, uuid_string, offset);

        int meta_fd = co_await _queue.open(
            meta_path.c_str(), O_EXCL | O_CREAT | O_WRONLY | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        );

        std::exception_ptr eptr;
        try {
            RawstorObjectSyncStateValue state{};
            RawstorObjectConfig config{};
            RawstorObjectBallot promised{};
            RawstorObjectBallot accepted{};
            state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;

            // The placement identity (docs/mds.md, chunk_meta) is
            // stamped now, from the caller's own spec, and never touched
            // again -- _write_meta() below preserves it unchanged.
            ChunkIdentity identity;
            identity.member_role = member_role;
            identity.width = static_cast<uint8_t>(sp.width);
            identity.chunk_size = sp.chunk_size;
            identity.size = sp.size;

            // meta_encode()'s own (shorter, variable-length) return value
            // is NUL-padded out to a fixed META_MAX_SIZE bytes here,
            // rather than written at its own length, so this file's own
            // byte length stays fixed across every rewrite -- see
            // _write_meta() below for why that matters.
            std::string encoded =
                meta_encode(state, config, promised, accepted, identity);
            std::array<char, META_MAX_SIZE> disk{};
            memcpy(disk.data(), encoded.data(), encoded.size());

            co_await _queue.pwrite(meta_fd, disk.data(), disk.size(), 0, true);
        } catch (...) {
            eptr = std::current_exception();
        }
        co_await _queue.close(meta_fd);
        if (eptr) {
            try {
                co_await _queue.unlink(meta_path.c_str());
            } catch (const std::system_error&) {
            }
            std::rethrow_exception(eptr);
        }
    } catch (...) {
        // co_await is not permitted inside a catch handler -- stash the
        // exception and rethrow it once out of the handler, below, after
        // the cleanup co_await.
        meta_error = std::current_exception();
    }

    if (meta_error) {
        // Best-effort: unlink() failing here must not replace meta_error
        // with one of its own.
        try {
            co_await _queue.unlink(target_path.c_str());
        } catch (...) {
        }
        std::rethrow_exception(meta_error);
    }

    co_return;
}

rawstd::Task<void>
Backend::remove(const RawstdUUID&, const RawstdUUID& id, uint64_t offset) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_dir = get_target_dir(location_path, uuid_string, offset);

    // The versions are copies of this chunk and go with it: they are
    // removed first (remove_version()), or an object created later under
    // the same id would show them as its own. Nothing of the live chunk is
    // unlinked until they are all gone, so a retry after a failure finishes
    // the job.
    std::error_code versions_error;
    if (std::filesystem::is_directory(target_dir, versions_error)) {
        for (const RawstdUUID& version_id : versions_in(target_dir)) {
            co_await remove_version({}, id, offset, version_id);
        }
    }

    // Either file may already be gone: a Slot retries remove() after a
    // transient failure (e.g. ENOBUFS from a saturated queue), possibly
    // one that hit between the two unlinks below. The chunk is missing
    // (ENOENT) only if neither file was there.
    bool found = false;
    try {
        co_await _queue.unlink(
            get_target_path(location_path, uuid_string, offset).c_str()
        );
        found = true;
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }

    try {
        co_await _queue.unlink(
            get_target_meta_path(location_path, uuid_string, offset).c_str()
        );
        found = true;
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }

    if (!found) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    // Best-effort cleanup of the now-empty directory chain -- rmdir()
    // fails ENOTEMPTY, silently tolerated, the moment a sibling still
    // lives there: another offset under the same uuid (the uuid
    // directory), or -- once a backend actually creates one -- a
    // surviving version under this same offset (this directory).
    if (rmdir(target_dir.c_str()) == -1) {
        errno = 0;
    } else if (rmdir((location_path + "/" + uuid_string).c_str()) == -1) {
        errno = 0;
    }
}

rawstd::Task<std::vector<RawstorObjectMeta>> Backend::meta(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& version_id
) {
    std::string location_path = get_location_path(location());

    std::error_code location_error;
    if (!std::filesystem::is_directory(location_path, location_error)) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
    }

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path =
        get_target_path(location_path, uuid_string, offset, version_id);
    std::string meta_path =
        get_target_meta_path(location_path, uuid_string, offset, version_id);

    struct stat st;
    co_await _queue.stat(target_path.c_str(), &st);

    int fd = co_await _queue.open(meta_path.c_str(), O_RDONLY | O_CLOEXEC, 0);

    RawstorObjectSyncStateValue state{};
    RawstorObjectConfig config{};
    RawstorObjectBallot promised{};
    RawstorObjectBallot accepted{};
    ChunkIdentity identity;
    std::exception_ptr eptr;
    try {
        std::array<char, META_MAX_SIZE> disk{};
        size_t rval = co_await _queue.pread(fd, disk.data(), disk.size(), 0);
        if (rval != disk.size()) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EILSEQ);
        }
        try {
            meta_decode(
                std::string(disk.data()), &state, &config, &promised, &accepted,
                &identity
            );
        } catch (const std::system_error&) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            throw;
        }
    } catch (...) {
        eptr = std::current_exception();
    }
    co_await _queue.close(fd);
    if (eptr) {
        std::rethrow_exception(eptr);
    }

    RawstorObjectMeta ret{};
    ret.spec.size = identity.size;
    ret.spec.width = identity.width;
    ret.spec.chunk_size = identity.chunk_size;
    ret.member_role = identity.member_role;
    ret.state = state;
    ret.config = config;
    ret.promised = promised;
    ret.accepted = accepted;

    co_return std::vector<RawstorObjectMeta>{ret};
}

rawstd::Task<void> Backend::_write_meta(
    const RawstdUUID& id, uint64_t offset, RawstorObjectSyncStateValue state,
    const RawstorObjectConfig& config, const RawstorObjectBallot& promised,
    const RawstorObjectBallot& accepted
) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string meta_path =
        get_target_meta_path(location_path, uuid_string, offset);

    // O_TRUNC would be wrong here regardless of the record carrying no
    // size of its own: this file is fixed-size, and a short write must
    // not leave a truncated, unparseable record behind.
    int fd = co_await _queue.open(meta_path.c_str(), O_RDWR | O_CLOEXEC, 0);

    std::exception_ptr eptr;
    try {
        // The placement identity is immutable once stamped at create() --
        // read the existing record first and carry it through unchanged,
        // rather than clobbering it with a zeroed one.
        std::array<char, META_MAX_SIZE> disk{};
        size_t got = co_await _queue.pread(fd, disk.data(), disk.size(), 0);
        if (got != disk.size()) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EILSEQ);
        }
        // Preserve the logical size and placement identity across rewrites.
        // An unreadable record cannot supply those fields and is rejected.
        RawstorObjectSyncStateValue old_record_state{};
        RawstorObjectConfig old_record_config{};
        RawstorObjectBallot old_record_promised{};
        RawstorObjectBallot old_record_accepted{};
        ChunkIdentity identity{};
        meta_decode(
            std::string(disk.data()), &old_record_state, &old_record_config,
            &old_record_promised, &old_record_accepted, &identity
        );

        // See create()'s own comment: NUL-padded out to a fixed
        // META_MAX_SIZE bytes so this file's own byte length stays fixed
        // across every rewrite -- required here specifically, since this
        // is an in-place overwrite without O_TRUNC (see above).
        std::string encoded =
            meta_encode(state, config, promised, accepted, identity);
        disk.fill('\0');
        memcpy(disk.data(), encoded.data(), encoded.size());

        size_t rval =
            co_await _queue.pwrite(fd, disk.data(), disk.size(), 0, true);
        if (rval != disk.size()) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }
    } catch (...) {
        eptr = std::current_exception();
    }
    co_await _queue.close(fd);
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

namespace {

// The fake snapshot is copied one block at a time through the Queue, so the
// event loop keeps serving other requests between blocks.
constexpr size_t copy_block_size = 1u << 20;

bool all_zero(const char* data, size_t size) {
    return size == 0 || (data[0] == 0 && memcmp(data, data + 1, size - 1) == 0);
}

// Copies `source` to a new file `target`, synced before it returns. The
// copy keeps the source's holes: it is the source's size first, and a block
// that reads back as zeros is never written.
rawstd::Task<void> copy_blocks(
    rawio::Queue& queue, const std::string& source, const std::string& target
) {
    struct stat st;
    co_await queue.stat(source.c_str(), &st);

    int in_fd = co_await queue.open(source.c_str(), O_RDONLY | O_CLOEXEC, 0);
    int out_fd = -1;
    std::exception_ptr eptr;
    try {
        // The staging name is this attempt's own, so whatever is there is a
        // leftover (possibly one with looser permissions than a file made
        // now would get): replaced, never reopened.
        if (unlink(target.c_str()) == -1 && errno != ENOENT) {
            RAWSTD_THROW_ERRNO();
        }
        out_fd = co_await queue.open(
            target.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        );
        if (ftruncate(out_fd, st.st_size) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        std::vector<char> block(copy_block_size);
        off_t pos = 0;
        while (pos < st.st_size) {
            size_t want = static_cast<size_t>(
                std::min<off_t>(block.size(), st.st_size - pos)
            );
            size_t got = co_await queue.pread(in_fd, block.data(), want, pos);
            if (got == 0) {
                // The source ended before its size said it would.
                RAWSTD_THROW_SYSTEM_ERROR(EIO);
            }
            if (!all_zero(block.data(), got)) {
                size_t done = 0;
                while (done < got) {
                    done += co_await queue.pwrite(
                        out_fd, block.data() + done, got - done, pos + done,
                        false
                    );
                }
            }
            pos += static_cast<off_t>(got);
        }
        co_await queue.fsync(out_fd, false);
    } catch (...) {
        eptr = std::current_exception();
    }
    if (out_fd != -1) {
        co_await queue.close(out_fd);
    }
    co_await queue.close(in_fd);
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

rawstd::Task<void> sync_dir(rawio::Queue& queue, const std::string& path) {
    int fd = co_await queue.open(path.c_str(), O_RDONLY | O_CLOEXEC, 0);
    std::exception_ptr eptr;
    try {
        co_await queue.fsync(fd, false);
    } catch (...) {
        eptr = std::current_exception();
    }
    co_await queue.close(fd);
    if (eptr) {
        std::rethrow_exception(eptr);
    }
}

// Staging files of one create_version() attempt, named apart from every
// other attempt's, so that attempts at the same version neither share a
// half-written file nor clean up each other's.
std::string staging_suffix() {
    static std::atomic<uint64_t> counter{0};
    return ".partial." + std::to_string(getpid()) + "." +
           std::to_string(counter.fetch_add(1));
}

} // namespace

rawstd::Task<void> Backend::create_version(
    const RawstdUUID&, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& version_id
) {
    if (rawstd_uuid_is_nil(&version_id)) {
        // nil is the live version, never a created one.
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string source = get_target_path(location_path, uuid_string, offset);
    std::string target_dir = get_target_dir(location_path, uuid_string, offset);
    std::string version_dir =
        get_target_dir(location_path, uuid_string, offset, version_id);
    std::string target = version_dir + "/data";
    std::string meta_source =
        get_target_meta_path(location_path, uuid_string, offset);
    std::string meta_target = version_dir + "/meta";
    std::string suffix = staging_suffix();
    std::string partial = target + suffix;
    std::string meta_partial = meta_target + suffix;

    // A retry after a completed copy finds the version already there --
    // possibly one whose attempt failed after the rename and before the
    // directories were synced, so they are synced here too before it is
    // reported.
    std::error_code ec;
    if (std::filesystem::exists(target, ec)) {
        co_await sync_dir(_queue, version_dir);
        co_await sync_dir(_queue, target_dir);
        co_return;
    }

    struct stat st;
    co_await _queue.stat(source.c_str(), &st);

    mkdir_or_exist(version_dir);

    // Both files are staged and synced first; `data` is renamed last, since
    // a version exists once it has one, and the directories are synced after
    // the renames, so a version that was reported created survives a crash.
    std::exception_ptr eptr;
    try {
        co_await copy_blocks(_queue, source, partial);
        co_await copy_blocks(_queue, meta_source, meta_partial);
        if (rename(meta_partial.c_str(), meta_target.c_str()) == -1) {
            RAWSTD_THROW_ERRNO();
        }
        if (rename(partial.c_str(), target.c_str()) == -1) {
            RAWSTD_THROW_ERRNO();
        }
        co_await sync_dir(_queue, version_dir);
        co_await sync_dir(_queue, target_dir);
    } catch (...) {
        eptr = std::current_exception();
    }
    if (eptr) {
        // Only this attempt's own staging files: a published `meta` may be
        // another attempt's, whose `data` is still to come. One left without
        // `data` is replaced by the next attempt and removed by
        // remove_version().
        unlink(partial.c_str());
        unlink(meta_partial.c_str());
        rmdir(version_dir.c_str());
        errno = 0;
        std::rethrow_exception(eptr);
    }

    co_return;
}

rawstd::Task<void> Backend::remove_version(
    const RawstdUUID&, const RawstdUUID& id, uint64_t offset,
    const RawstdUUID& version_id
) {
    if (rawstd_uuid_is_nil(&version_id)) {
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string version_dir =
        get_target_dir(location_path, uuid_string, offset, version_id);

    std::error_code ec;
    bool found = false;
    // Staging files an interrupted create_version() left behind go with the
    // version.
    std::vector<std::filesystem::path> staging;
    for (const auto& entry :
         std::filesystem::directory_iterator(version_dir, ec)) {
        std::string name = entry.path().filename().string();
        if (name.rfind("data.partial.", 0) == 0 ||
            name.rfind("meta.partial.", 0) == 0) {
            staging.push_back(entry.path());
        }
    }
    // No directory at all is a version that is not there (ENOENT below).
    if (ec && ec != std::errc::no_such_file_or_directory) {
        RAWSTD_THROW_SYSTEM_ERROR(ec.value());
    }
    for (const auto& path : staging) {
        ec.clear();
        found = std::filesystem::remove(path, ec) || found;
        if (ec) {
            RAWSTD_THROW_SYSTEM_ERROR(ec.value());
        }
    }
    ec.clear();
    found = std::filesystem::remove(version_dir + "/data", ec) || found;
    if (ec) {
        RAWSTD_THROW_SYSTEM_ERROR(ec.value());
    }
    found = std::filesystem::remove(version_dir + "/meta", ec) || found;
    if (ec) {
        RAWSTD_THROW_SYSTEM_ERROR(ec.value());
    }
    if (rmdir(version_dir.c_str()) == 0) {
        found = true;
    } else if (errno != ENOENT) {
        // Something unexpected is left in it: not removed.
        RAWSTD_THROW_ERRNO();
    }
    errno = 0;
    if (!found) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    co_return;
}

rawstd::Task<std::vector<RawstdUUID>>
Backend::list_versions(const RawstdUUID& id, uint64_t offset) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_dir = get_target_dir(location_path, uuid_string, offset);
    if (!std::filesystem::exists(target_dir + "/data")) {
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    co_return versions_in(target_dir);
}

rawstd::Task<RawstorLocationInfo> Backend::info() {
    RawstorLocationInfo ret = {};
    try {
        std::string location_path = get_location_path(location());

        struct statvfs vfs;
        if (statvfs(location_path.c_str(), &vfs) == -1) {
            RAWSTD_THROW_ERRNO();
        }
        uint64_t available = static_cast<uint64_t>(vfs.f_bavail) * vfs.f_frsize;

        uint64_t used = 0;
        // TODO: std::filesystem::directory_iterator itself still blocks
        // the event loop scanning this directory -- io_uring has no
        // readdir/getdents opcode to make that part async too, only
        // IORING_OP_STATX for the per-entry stat() below (already async
        // via _queue.stat()). Recursive now that each object's own
        // `data`/`meta` live a directory (or two) deep
        // (get_target_dir()'s own doc comment) rather than directly
        // under location_path -- every directory level along the way is
        // skipped by the is_regular_file() check, only the leaf files
        // themselves are stat()ed and summed.
        for (const auto& entry :
             std::filesystem::recursive_directory_iterator(location_path)) {
            if (!entry.is_regular_file()) {
                continue;
            }
            struct stat st;
            try {
                co_await _queue.stat(entry.path().c_str(), &st);
            } catch (const std::system_error& e) {
                if (e.code().value() == ENOENT) {
                    // Object removed concurrently between the directory
                    // read and this stat(); just skip it rather than
                    // failing the whole aggregate.
                    continue;
                }
                throw;
            }
            used += static_cast<uint64_t>(st.st_size);
        }
        ret.used = used;
        ret.total = used + available;
    } catch (const std::system_error&) {
        throw;
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    } catch (...) {
        rawstd_error("Unexpected error\n");
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    co_return ret;
}

} // namespace file
} // namespace rawstor
