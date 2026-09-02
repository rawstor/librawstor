#include "file_backend.hpp"

#include "opts.h"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/gcc.h>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
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
// companion "<uuid>.meta" file, versioned so the format can grow later
// without breaking copies written by an older release.
constexpr uint32_t META_FORMAT_VERSION = 1;

struct OnDiskMeta {
    uint32_t magic;
    uint32_t version;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    uint32_t state;
};

OnDiskMeta meta_to_disk(const RawstorObjectMeta& meta) {
    OnDiskMeta disk{};
    disk.magic = RAWSTOR_MAGIC;
    disk.version = META_FORMAT_VERSION;
    disk.epoch = meta.epoch;
    disk.sync_id = meta.sync_id;
    memcpy(
        disk.sync_id_history, meta.sync_id_history, sizeof(disk.sync_id_history)
    );
    disk.state = meta.state;
    return disk;
}

RawstorObjectMeta disk_to_meta(const OnDiskMeta& disk) {
    RawstorObjectMeta meta{};
    meta.epoch = disk.epoch;
    meta.sync_id = disk.sync_id;
    memcpy(
        meta.sync_id_history, disk.sync_id_history, sizeof(meta.sync_id_history)
    );
    meta.state = disk.state;
    return meta;
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

        if (::close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        unlink(target_path.c_str());
        ::close(fd);
        throw;
    }

    // A fresh copy starts with sync_id 0: it has never been part of an
    // established sync set (see docs/mirroring.md). Written after the data
    // file so a crash between the two never leaves a .meta file without
    // its data file; set_state()/meta() failing ENOENT on the reverse
    // (data file present, no .meta yet) is exactly case F10.
    try {
        std::string meta_path = get_target_meta_path(location_path, uuid_string);

        int meta_fd = co_await _queue.open(
            meta_path.c_str(), O_EXCL | O_CREAT | O_WRONLY | O_CLOEXEC,
            S_IRUSR | S_IWUSR
        );

        std::exception_ptr eptr;
        try {
            RawstorObjectMeta meta{};
            meta.state = RAWSTOR_OBJECT_STATE_CLEAN;
            OnDiskMeta disk = meta_to_disk(meta);

            co_await _queue.pwrite(meta_fd, &disk, sizeof(disk), 0, true);
        } catch (...) {
            eptr = std::current_exception();
        }
        co_await _queue.close(meta_fd);
        if (eptr) {
            unlink(meta_path.c_str());
            std::rethrow_exception(eptr);
        }
    } catch (...) {
        unlink(target_path.c_str());
        throw;
    }

    co_return;
}

rawstd::Task<void> Backend::remove(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);
    if (unlink(target_path.c_str()) == -1) {
        RAWSTD_THROW_ERRNO();
    }

    std::string meta_path = get_target_meta_path(location_path, uuid_string);
    if (unlink(meta_path.c_str()) == -1 && errno != ENOENT) {
        RAWSTD_THROW_ERRNO();
    }

    co_return;
}

rawstd::Task<RawstorObjectSpec> Backend::spec(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);

    RawstorObjectSpec ret{
        .size = std::filesystem::file_size(target_path),
    };

    co_return ret;
}

rawstd::Task<RawstorObjectMeta> Backend::meta(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string meta_path = get_target_meta_path(location_path, uuid_string);

    int fd = co_await _queue.open(meta_path.c_str(), O_RDONLY | O_CLOEXEC, 0);

    RawstorObjectMeta ret{};
    std::exception_ptr eptr;
    try {
        OnDiskMeta disk{};
        size_t rval = co_await _queue.pread(fd, &disk, sizeof(disk), 0);
        if (rval != sizeof(disk) || disk.magic != RAWSTOR_MAGIC) {
            rawstd_error("Malformed object meta: %s\n", meta_path.c_str());
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        if (disk.version != META_FORMAT_VERSION) {
            rawstd_error(
                "Unsupported object meta version: %u\n", disk.version
            );
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        ret = disk_to_meta(disk);
    } catch (...) {
        eptr = std::current_exception();
    }
    co_await _queue.close(fd);
    if (eptr) {
        std::rethrow_exception(eptr);
    }

    std::string target_path = get_target_path(location_path, uuid_string);
    ret.size = std::filesystem::file_size(target_path);

    co_return ret;
}

rawstd::Task<void>
Backend::set_state(const RawstdUUID& id, const RawstorObjectMeta& meta) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string meta_path = get_target_meta_path(location_path, uuid_string);

    // meta's own size field is ignored (the stored size always comes from
    // the data file itself, see spec()/meta() above) -- O_TRUNC would be
    // wrong here regardless: this file is fixed-size, and a short write
    // must not leave a truncated, unparseable record behind.
    int fd = co_await _queue.open(meta_path.c_str(), O_WRONLY | O_CLOEXEC, 0);

    std::exception_ptr eptr;
    try {
        OnDiskMeta disk = meta_to_disk(meta);
        size_t rval = co_await _queue.pwrite(fd, &disk, sizeof(disk), 0, true);
        if (rval != sizeof(disk)) {
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
