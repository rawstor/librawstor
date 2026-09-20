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
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>

namespace {

// One chunk's own directory: <location>/<uuid>/<offset> --
// self-describing: `uuid` is the same id every chunk of that id carries,
// `offset` (0 for a plain object) disambiguates which chunk of that
// id this is. Two files live directly under this directory: `data` (the
// object's own bytes) and `meta` (get_target_meta_path() below). `offset`
// is hex, not decimal -- same base as the target URI's own offset path
// segment (Target::parse_path()'s own doc comment) and every numeric
// field meta_encode() persists alongside it, so a directory listing and
// its own meta record read the same way.
std::string get_target_dir(
    const std::string& location_path, const RawstdUUIDString& uuid,
    uint64_t offset
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << "/" << std::hex << offset;

    return oss.str();
}

std::string get_target_path(
    const std::string& location_path, const RawstdUUIDString& uuid,
    uint64_t offset
) {
    return get_target_dir(location_path, uuid, offset) + "/data";
}

std::string get_target_meta_path(
    const std::string& location_path, const RawstdUUIDString& uuid,
    uint64_t offset
) {
    return get_target_dir(location_path, uuid, offset) + "/meta";
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

rawstd::Task<int> Backend::_open(
    const RawstdUUID& id, uint64_t offset, const RawstdUUID& snap_id
) {
    if (!rawstd_uuid_is_nil(&snap_id)) {
        /* No native CoW. */
        RAWSTD_THROW_SYSTEM_ERROR(ENOTSUP);
    }

    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);

    std::string target_path = get_target_path(location_path, id_string, offset);

    // O_CLOEXEC: a file:// backend can be live in the same process as an
    // lvm:// or zfs:// one (Target::open() fans out across every URI of a
    // target concurrently, src/target.cpp), whose create()/remove() shell
    // out via fork()+exec() (src/subprocess.cpp) -- without it, this fd
    // would leak into those children.
    int fd = co_await _queue.open(
        target_path.c_str(), O_RDWR | O_NONBLOCK | O_CLOEXEC, 0
    );
    co_return fd;
}

rawstd::Task<void> Backend::list(
    unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    RawstdUUID input_token = token;
    targets.clear();
    token = {};
    try {
        std::string location_path = get_location_path(location());

        // One entry per id directory (<location>/<uuid>/), regardless of
        // how many offset subdirectories it holds -- nothing today
        // ever creates more than one offset under the same id, so this
        // stays UUID-only (multi-chunk listing is a later concern).
        for (const auto& entry :
             std::filesystem::directory_iterator(location_path)) {
            if (!entry.is_directory()) {
                continue;
            }
            std::string dirname = entry.path().filename().string();

            RawstdUUID uuid;
            int res = rawstd_uuid_from_string(&uuid, dirname.c_str());
            if (res < 0) {
                rawstd_warning(
                    "%s: %s\n", strerror(-res), entry.path().string().c_str()
                );
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
    const RawstdUUID& id, uint64_t offset, const RawstorObjectSpec& sp
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
            co_await _queue.fallocate(fd, 0, 0, static_cast<off_t>(sp.size));
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
    // its data file; set_sync_state()/meta() failing ENOENT on the reverse
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
            RawstorObjectSyncState sync_state{};
            sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;

            ChunkIdentity identity{};
            identity.width = static_cast<uint8_t>(sp.width);
            identity.chunk_size = sp.chunk_size;

            // meta_encode()'s own (shorter, variable-length) return value
            // is NUL-padded out to a fixed META_MAX_SIZE bytes here,
            // rather than written at its own length, so this file's own
            // byte length stays fixed across every rewrite -- see
            // set_sync_state() below for why that matters.
            std::string encoded = meta_encode(sync_state, identity);
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

rawstd::Task<void> Backend::remove(const RawstdUUID& id, uint64_t offset) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_dir = get_target_dir(location_path, uuid_string, offset);
    co_await _queue.unlink(
        get_target_path(location_path, uuid_string, offset).c_str()
    );

    try {
        co_await _queue.unlink(
            get_target_meta_path(location_path, uuid_string, offset).c_str()
        );
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }

    // Best-effort cleanup of the now-empty directory chain -- rmdir()
    // fails ENOTEMPTY, silently tolerated, the moment a sibling still
    // lives there: another offset under the same uuid directory.
    if (rmdir(target_dir.c_str()) == -1) {
        errno = 0;
    } else if (rmdir((location_path + "/" + uuid_string).c_str()) == -1) {
        errno = 0;
    }
}

rawstd::Task<RawstorObjectMeta>
Backend::meta(const RawstdUUID& id, uint64_t offset) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path =
        get_target_path(location_path, uuid_string, offset);
    std::string meta_path =
        get_target_meta_path(location_path, uuid_string, offset);

    struct stat st;
    co_await _queue.stat(target_path.c_str(), &st);

    int fd = co_await _queue.open(meta_path.c_str(), O_RDONLY | O_CLOEXEC, 0);

    RawstorObjectSyncState sync_state{};
    ChunkIdentity identity{};
    std::exception_ptr eptr;
    try {
        std::array<char, META_MAX_SIZE> disk{};
        size_t rval = co_await _queue.pread(fd, disk.data(), disk.size(), 0);
        if (rval != disk.size()) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        try {
            meta_decode(std::string(disk.data()), &sync_state, &identity);
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
    ret.spec.size = static_cast<uint64_t>(st.st_size);
    ret.spec.width = identity.width;
    ret.spec.chunk_size = identity.chunk_size;
    ret.sync_state = sync_state;

    co_return ret;
}

rawstd::Task<void> Backend::set_sync_state(
    const RawstdUUID& id, uint64_t offset,
    const RawstorObjectSyncState& sync_state
) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string meta_path =
        get_target_meta_path(location_path, uuid_string, offset);

    // O_TRUNC would be wrong here regardless of sync_state carrying no
    // size of its own: this file is fixed-size, and a short write must
    // not leave a truncated, unparseable record behind.
    int fd = co_await _queue.open(meta_path.c_str(), O_RDWR | O_CLOEXEC, 0);

    std::exception_ptr eptr;
    try {
        // Read the existing record first so overwriting sync_state here
        // doesn't clobber its own identity.
        std::array<char, META_MAX_SIZE> old_disk{};
        size_t old_rval =
            co_await _queue.pread(fd, old_disk.data(), old_disk.size(), 0);
        if (old_rval != old_disk.size()) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        // identity is stamped once at create() and never changed again --
        // preserve it across this rewrite. A record meta_decode() can't
        // parse (an earlier format version) has no identity to preserve;
        // it degenerates to the all-zero default, same as
        // lvm::Backend::set_sync_state()'s own equivalent fallback.
        RawstorObjectSyncState old_sync_state{};
        ChunkIdentity identity{};
        try {
            meta_decode(
                std::string(old_disk.data()), &old_sync_state, &identity
            );
        } catch (const std::system_error&) {
            identity = ChunkIdentity{};
        }

        // See create()'s own comment: NUL-padded out to a fixed
        // META_MAX_SIZE bytes so this file's own byte length stays fixed
        // across every rewrite -- required here specifically, since this
        // is an in-place overwrite without O_TRUNC (see above).
        std::string encoded = meta_encode(sync_state, identity);
        std::array<char, META_MAX_SIZE> disk{};
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
        // `data`/`meta` live a directory deep (get_target_dir()'s own
        // doc comment) rather than directly under location_path.
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
