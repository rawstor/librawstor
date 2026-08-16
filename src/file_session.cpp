#include "file_session.hpp"

#include "opts.h"
#include "worker.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace {

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

/*
 * On-disk mirror metadata, stored in a "<uuid>.meta" sidecar next to the
 * object's data file (see docs/mirroring.md). The data file itself stays a
 * bare "<uuid>" holding nothing but object data, so a copy with no sidecar
 * -- an object created before mirroring, or by an older release -- is a
 * legacy copy: CLEAN with sync_id 0, never part of an established sync set.
 */
constexpr uint32_t META_FORMAT_VERSION = 2;

struct OnDiskMeta {
    uint32_t magic;
    uint32_t version;
    uint64_t size;
    uint64_t epoch;
    uint64_t sync_id;
    uint64_t sync_id_history[RAWSTOR_OBJECT_SYNC_ID_HISTORY];
    uint32_t state;
    /*
     * Placement identity (rawstor_docs/Mds.md, chunk_meta); immutable:
     * a chunk is (volume_id, offset = logical_index * chunk_size, length).
     */
    uint8_t member_kind;
    uint8_t width;
    uint8_t pad[2];
    uint8_t volume_id[16];
    uint64_t logical_index;
    uint64_t chunk_size;
    uint64_t snap_version;
    /* Reserved for future extensions (snapshot list, stored checksums). */
    uint8_t reserved[80];
};

static_assert(sizeof(OnDiskMeta) == 192);

std::string
get_meta_path(const std::string& location_path, const RawstdUUIDString& uuid) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << ".meta";

    return oss.str();
}

OnDiskMeta meta_to_disk(const RawstorObjectMeta& meta) {
    OnDiskMeta disk{};
    disk.magic = RAWSTOR_MAGIC;
    disk.version = META_FORMAT_VERSION;
    disk.size = meta.size;
    disk.epoch = meta.epoch;
    disk.sync_id = meta.sync_id;
    memcpy(
        disk.sync_id_history, meta.sync_id_history, sizeof(disk.sync_id_history)
    );
    disk.state = meta.state;
    disk.member_kind = meta.member_kind;
    disk.width = meta.width;
    memcpy(disk.volume_id, meta.volume_id, sizeof(disk.volume_id));
    disk.logical_index = meta.logical_index;
    disk.chunk_size = meta.chunk_size;
    disk.snap_version = meta.snap_version;
    return disk;
}

RawstorObjectMeta disk_to_meta(const OnDiskMeta& disk) {
    RawstorObjectMeta meta{};
    meta.size = disk.size;
    meta.epoch = disk.epoch;
    meta.sync_id = disk.sync_id;
    memcpy(
        meta.sync_id_history, disk.sync_id_history, sizeof(meta.sync_id_history)
    );
    meta.state = disk.state;
    meta.member_kind = disk.member_kind;
    meta.width = disk.width;
    memcpy(meta.volume_id, disk.volume_id, sizeof(meta.volume_id));
    meta.logical_index = disk.logical_index;
    meta.chunk_size = disk.chunk_size;
    meta.snap_version = disk.snap_version;
    return meta;
}

/* A missing sidecar is a legacy copy, not an error -- see above. */
RawstorObjectMeta read_meta_path(const std::string& path) {
    int fd = ::open(path.c_str(), O_RDONLY);
    if (fd == -1) {
        if (errno == ENOENT) {
            errno = 0;

            RawstorObjectMeta meta{};
            meta.state = RAWSTOR_OBJECT_STATE_CLEAN;
            return meta;
        }
        RAWSTD_THROW_ERRNO();
    }

    OnDiskMeta disk{};
    ssize_t rval = ::pread(fd, &disk, sizeof(disk), 0);
    int error = rval == -1 ? errno : 0;
    ::close(fd);
    if (error) {
        errno = 0;
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    if (rval != sizeof(disk) || disk.magic != RAWSTOR_MAGIC) {
        rawstd_error("Malformed object metadata: %s\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    if (disk.version != META_FORMAT_VERSION) {
        rawstd_error("Unsupported object metadata version: %u\n", disk.version);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    return disk_to_meta(disk);
}

/* Durable by the time it returns: the caller relies on that. */
void write_meta_path(const std::string& path, const RawstorObjectMeta& meta) {
    int fd = ::open(path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        OnDiskMeta disk = meta_to_disk(meta);
        ssize_t res = ::pwrite(fd, &disk, sizeof(disk), 0);
        if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }
        if (res != sizeof(disk)) {
            RAWSTD_THROW_SYSTEM_ERROR(EIO);
        }

        if (::fsync(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (::close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        ::close(fd);
        throw;
    }
}

void fsync_path(const std::string& path, int flags) {
    int fd = ::open(path.c_str(), flags);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (::fsync(fd) == -1) {
        int error = errno;
        errno = 0;
        ::close(fd);
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }
    if (::close(fd) == -1) {
        RAWSTD_THROW_ERRNO();
    }
}

} // unnamed namespace

namespace rawstor {
namespace file {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Session(p, queue, location) {
}

void Session::_connect(
    const RawstdUUID& id, uint64_t snap, std::function<void(int)>&& cb
) {
    /* No CoW on plain files: no snapshot version to bind. */
    if (snap != 0) {
        cb(-ENOTSUP);
        return;
    }

    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);

    /*
     * The path buffer is kept alive by the callback capture: io_uring reads
     * the string when the openat operation is executed, not when submitted.
     */
    auto target_path = std::make_shared<std::string>(
        get_target_path(location_path, id_string)
    );

    rawstd_info("Connecting to %s...\n", location().str().c_str());

    _queue.open(
        target_path->c_str(), O_RDWR | O_NONBLOCK, 0,
        [target_path, cb = std::move(cb)](int result) {
            if (result >= 0) {
                rawstd_info("fd %d: Connected\n", result);
            }
            cb(result);
        }
    );
}

void Session::list(
    unsigned int limit, const RawstdUUID& token,
    std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&& cb
) {
    std::vector<RawstdUUID> ret_uuids;
    RawstdUUID ret_token = {};
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

            ret_uuids.push_back(uuid);
        }

        std::sort(
            ret_uuids.begin(), ret_uuids.end(),
            [](const RawstdUUID& lhs, const RawstdUUID& rhs) {
                return rawstd_uuid_cmp(&lhs, &rhs) < 0;
            }
        );

        ret_uuids.erase(
            ret_uuids.begin(),
            std::upper_bound(
                ret_uuids.begin(), ret_uuids.end(), token,
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

        if (ret_uuids.size() > limit) {
            ret_uuids.resize(limit);
            ret_token = ret_uuids.back();
        }
    } catch (const std::system_error& e) {
        cb({}, {}, e.code().value());
        return;
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        cb({}, {}, EIO);
        return;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        cb({}, {}, EIO);
        return;
    }

    cb(std::move(ret_uuids), ret_token, 0);
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    run_in_worker(
        _queue,
        [location = location(), id, sp]() -> int {
            std::string location_path = get_location_path(location);
            if (mkdir(location_path.c_str(), 0755) == -1) {
                if (errno == EEXIST) {
                    errno = 0;
                } else {
                    RAWSTD_THROW_ERRNO();
                }
            }

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string target_path =
                get_target_path(location_path, uuid_string);

            int fd = ::open(
                target_path.c_str(), O_EXCL | O_CREAT | O_WRONLY,
                S_IRUSR | S_IWUSR
            );
            if (fd == -1) {
                RAWSTD_THROW_ERRNO();
            }

            std::string meta_path = get_meta_path(location_path, uuid_string);

            try {
                if (ftruncate(fd, sp.size) == -1) {
                    RAWSTD_THROW_ERRNO();
                }

                if (::fsync(fd) == -1) {
                    RAWSTD_THROW_ERRNO();
                }

                if (::close(fd) == -1) {
                    RAWSTD_THROW_ERRNO();
                }

                /*
                 * A fresh copy starts with sync_id 0: it has never been part
                 * of an established sync set (see docs/mirroring.md).
                 */
                RawstorObjectMeta meta{};
                meta.size = sp.size;
                meta.state = RAWSTOR_OBJECT_STATE_CLEAN;
                meta.member_kind = sp.member_kind;
                meta.width = sp.width;
                memcpy(meta.volume_id, sp.volume_id, sizeof(meta.volume_id));
                meta.logical_index = sp.logical_index;
                meta.chunk_size = sp.chunk_size;
                meta.snap_version = sp.snap_version;

                write_meta_path(meta_path, meta);

                fsync_path(location_path, O_RDONLY | O_DIRECTORY);
            } catch (...) {
                unlink(meta_path.c_str());
                unlink(target_path.c_str());
                ::close(fd);
                throw;
            }

            return 0;
        },
        std::move(cb)
    );
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    run_in_worker(
        _queue,
        [location = location(), id]() -> int {
            std::string location_path = get_location_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string meta_path = get_meta_path(location_path, uuid_string);
            if (unlink(meta_path.c_str()) == -1) {
                if (errno == ENOENT) {
                    errno = 0;
                } else {
                    RAWSTD_THROW_ERRNO();
                }
            }

            std::string target_path =
                get_target_path(location_path, uuid_string);
            if (unlink(target_path.c_str()) == -1) {
                RAWSTD_THROW_ERRNO();
            }

            return 0;
        },
        std::move(cb)
    );
}

void Session::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    auto ret = std::make_shared<RawstorObjectSpec>();

    run_in_worker(
        _queue,
        [location = location(), id, ret]() -> int {
            std::string location_path = get_location_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string target_path =
                get_target_path(location_path, uuid_string);

            ret->size = std::filesystem::file_size(target_path);

            return 0;
        },
        [ret, cb = std::move(cb)](int error) { cb(*ret, error); }
    );
}

void Session::meta(
    const RawstdUUID& id, uint64_t snap,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    /* No CoW on plain files: there are no snapshot versions to query. */
    if (snap != 0) {
        cb({}, ENOTSUP);
        return;
    }

    auto ret = std::make_shared<RawstorObjectMeta>();

    run_in_worker(
        _queue,
        [location = location(), id, ret]() -> int {
            std::string location_path = get_location_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            /*
             * The size always comes from the data file, never from the
             * sidecar: the file is the object, the sidecar only records
             * what the file cannot say about itself.
             */
            *ret = read_meta_path(get_meta_path(location_path, uuid_string));
            ret->size = std::filesystem::file_size(
                get_target_path(location_path, uuid_string)
            );

            return 0;
        },
        [ret, cb = std::move(cb)](int error) { cb(*ret, error); }
    );
}

void Session::set_state(
    const RawstdUUID& id, const RawstorObjectMeta& meta,
    std::function<void(int)>&& cb
) {
    run_in_worker(
        _queue,
        [location = location(), id, meta]() -> int {
            std::string location_path = get_location_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string meta_path = get_meta_path(location_path, uuid_string);

            /*
             * The size is the data file's (the size field of meta is
             * ignored), and the placement identity is immutable: both are
             * carried over from what is already recorded.
             */
            RawstorObjectMeta stored = read_meta_path(meta_path);
            RawstorObjectMeta next = meta;
            next.size = std::filesystem::file_size(
                get_target_path(location_path, uuid_string)
            );
            next.member_kind = stored.member_kind;
            next.width = stored.width;
            memcpy(next.volume_id, stored.volume_id, sizeof(next.volume_id));
            next.logical_index = stored.logical_index;
            next.chunk_size = stored.chunk_size;
            next.snap_version = stored.snap_version;

            write_meta_path(meta_path, next);

            return 0;
        },
        std::move(cb)
    );
}

void Session::list_chunks(
    std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
) {
    auto ret = std::make_shared<std::vector<RawstorObjectListEntry>>();

    run_in_worker(
        _queue,
        [location = location(), ret]() -> int {
            std::string location_path = get_location_path(location);

            DIR* dir = ::opendir(location_path.c_str());
            if (dir == nullptr) {
                /* A location with no objects may not have a directory yet. */
                if (errno == ENOENT) {
                    errno = 0;
                    return 0;
                }
                RAWSTD_THROW_ERRNO();
            }

            try {
                const std::string suffix = ".meta";
                errno = 0;
                for (dirent* e = ::readdir(dir); e != nullptr;
                     e = ::readdir(dir)) {
                    std::string name = e->d_name;
                    if (name.size() <= suffix.size() ||
                        name.compare(
                            name.size() - suffix.size(), suffix.size(), suffix
                        ) != 0) {
                        errno = 0;
                        continue;
                    }

                    std::string stem =
                        name.substr(0, name.size() - suffix.size());
                    RawstorObjectListEntry entry{};
                    RawstdUUID id;
                    if (rawstd_uuid_from_string(&id, stem.c_str()) != 0) {
                        rawstd_error(
                            "%s/%s: not an object metadata record, skipped\n",
                            location_path.c_str(), name.c_str()
                        );
                        errno = 0;
                        continue;
                    }
                    memcpy(entry.obj_id, id.bytes, sizeof(entry.obj_id));

                    try {
                        entry.meta = read_meta_path(location_path + "/" + name);
                        /* The size is the data file's, as in meta(). */
                        entry.meta.size = std::filesystem::file_size(
                            location_path + "/" + stem
                        );
                        ret->push_back(entry);
                    } catch (const std::exception& err) {
                        rawstd_error(
                            "%s/%s: %s, skipped\n", location_path.c_str(),
                            name.c_str(), err.what()
                        );
                    }
                    errno = 0;
                }
                if (errno != 0) {
                    RAWSTD_THROW_ERRNO();
                }

                ::closedir(dir);
            } catch (...) {
                ::closedir(dir);
                throw;
            }

            return 0;
        },
        [ret, cb = std::move(cb)](int error) { cb(std::move(*ret), error); }
    );
}

void Session::snapshot(
    const RawstdUUID&, uint64_t, std::function<void(int)>&& cb
) {
    cb(ENOTSUP);
}

void Session::snap_remove(
    const RawstdUUID&, uint64_t, std::function<void(int)>&& cb
) {
    cb(ENOTSUP);
}

void Session::info(std::function<void(const RawstorLocationInfo&, int)>&& cb) {
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
    } catch (const std::system_error& e) {
        cb({}, e.code().value());
        return;
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        cb({}, EIO);
        return;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        cb({}, EIO);
        return;
    }

    cb(ret, 0);
}

} // namespace file
} // namespace rawstor
