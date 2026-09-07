#include "file_backend.hpp"

#include "blkdev_meta.hpp"
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

// Mirror consistency metadata for one copy (docs/mirroring.md) lives in a
// companion "<uuid>.meta" file, encoded the same way as the lvm:///zfs://
// backends' own native metadata (see src/blkdev_meta.hpp) instead of a
// bespoke binary format -- NUL-padded out to BLKDEV_META_MAX_SIZE bytes
// so this file's own byte length stays fixed across every rewrite (see
// Backend::set_sync_state() below for why that matters), rather than
// written at its own (shorter, variable) encoded length.
std::array<char, rawstor::BLKDEV_META_MAX_SIZE>
meta_to_disk(const RawstorObjectSyncState& sync_state) {
    std::array<char, rawstor::BLKDEV_META_MAX_SIZE> buf{};
    std::string encoded = rawstor::blkdev_meta_encode(sync_state);
    memcpy(buf.data(), encoded.data(), encoded.size());
    return buf;
}

std::string get_target_meta_path(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << ".meta";

    return oss.str();
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

std::string get_target_path(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid;

    return oss.str();
}

} // unnamed namespace

namespace rawstor {
namespace file {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Backend(p, queue, location) {
}

rawstd::Task<int> Backend::_open(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);

    std::string target_path = get_target_path(location_path, id_string);

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

        for (const auto& entry :
             std::filesystem::directory_iterator(location_path)) {
            if (!entry.path().extension().empty()) {
                continue;
            }
            std::string filename = entry.path().filename().string();

            RawstdUUID uuid;
            int res = rawstd_uuid_from_string(&uuid, filename.c_str());
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

rawstd::Task<void>
Backend::create(const RawstdUUID& id, const RawstorObjectSpec& sp) {
    _validate_mirrors_one(sp);

    std::string location_path = get_location_path(location());
    if (mkdir(location_path.c_str(), 0755) == -1) {
        if (errno == EEXIST) {
            errno = 0;
        } else {
            RAWSTD_THROW_ERRNO();
        }
    }

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);

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
    // file so a crash between the two never leaves a .meta file without
    // its data file; set_sync_state()/meta() failing ENOENT on the reverse
    // (data file present, no .meta yet) is exactly case F10.
    std::exception_ptr meta_error;
    try {
        std::string meta_path =
            get_target_meta_path(location_path, uuid_string);

        int meta_fd = co_await _queue.open(
            meta_path.c_str(), O_EXCL | O_CREAT | O_WRONLY | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        );

        std::exception_ptr eptr;
        try {
            RawstorObjectSyncState sync_state{};
            sync_state.state = RAWSTOR_OBJECT_SYNC_STATE_CLEAN;
            std::array<char, BLKDEV_META_MAX_SIZE> disk =
                meta_to_disk(sync_state);

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

rawstd::Task<void> Backend::remove(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);
    co_await _queue.unlink(target_path.c_str());

    std::string meta_path = get_target_meta_path(location_path, uuid_string);
    try {
        co_await _queue.unlink(meta_path.c_str());
    } catch (const std::system_error& e) {
        if (e.code().value() != ENOENT) {
            throw;
        }
    }
}

rawstd::Task<RawstorObjectSpec> Backend::spec(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);

    struct stat st;
    co_await _queue.stat(target_path.c_str(), &st);

    RawstorObjectSpec ret{
        .size = static_cast<uint64_t>(st.st_size),
        .mirrors = 1,
    };

    co_return ret;
}

rawstd::Task<RawstorObjectMeta> Backend::meta(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string meta_path = get_target_meta_path(location_path, uuid_string);

    int fd = co_await _queue.open(meta_path.c_str(), O_RDONLY | O_CLOEXEC, 0);

    RawstorObjectSyncState sync_state{};
    std::exception_ptr eptr;
    try {
        std::array<char, BLKDEV_META_MAX_SIZE> disk{};
        size_t rval = co_await _queue.pread(fd, disk.data(), disk.size(), 0);
        if (rval != disk.size() ||
            !blkdev_meta_decode(std::string(disk.data()), &sync_state)) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
    } catch (...) {
        eptr = std::current_exception();
    }
    co_await _queue.close(fd);
    if (eptr) {
        std::rethrow_exception(eptr);
    }

    RawstorObjectMeta ret{};
    ret.size = (co_await spec(id)).size;
    ret.sync_state = sync_state;

    co_return ret;
}

rawstd::Task<void> Backend::set_sync_state(
    const RawstdUUID& id, const RawstorObjectSyncState& sync_state
) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string meta_path = get_target_meta_path(location_path, uuid_string);

    // O_TRUNC would be wrong here regardless of sync_state carrying no
    // size of its own: this file is fixed-size, and a short write must
    // not leave a truncated, unparseable record behind.
    int fd = co_await _queue.open(meta_path.c_str(), O_WRONLY | O_CLOEXEC, 0);

    std::exception_ptr eptr;
    try {
        std::array<char, BLKDEV_META_MAX_SIZE> disk = meta_to_disk(sync_state);
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
        ret.total = static_cast<uint64_t>(vfs.f_blocks) * vfs.f_frsize;

        uint64_t used = 0;
        for (const auto& entry :
             std::filesystem::directory_iterator(location_path)) {
            if (!entry.path().extension().empty()) {
                continue;
            }

            struct stat st;
            if (stat(entry.path().c_str(), &st) == -1) {
                // Object removed concurrently between the directory read
                // and this stat(); just skip it rather than failing the
                // whole aggregate.
                continue;
            }
            used += static_cast<uint64_t>(st.st_size);
        }
        ret.used = used;
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
