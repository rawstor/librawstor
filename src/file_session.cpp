#include "file_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "worker.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <rawstor/protocol.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <memory>
#include <sstream>
#include <string>
#include <utility>

namespace {

/* On-disk .spec layout. */
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

RawstorObjectMeta read_meta_fd(int fd) {
    OnDiskMeta disk{};
    ssize_t rval = ::pread(fd, &disk, sizeof(disk), 0);
    if (rval == -1) {
        RAWSTD_THROW_ERRNO();
    }

    if (rval != sizeof(disk) || disk.magic != RAWSTOR_MAGIC) {
        rawstd_error("Malformed object spec\n");
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    if (disk.version != META_FORMAT_VERSION) {
        rawstd_error("Unsupported object spec version: %u\n", disk.version);
        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    return disk_to_meta(disk);
}

void write_meta_fd(int fd, const RawstorObjectMeta& meta) {
    OnDiskMeta disk = meta_to_disk(meta);
    ssize_t res = ::pwrite(fd, &disk, sizeof(disk), 0);
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (res != sizeof(disk)) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
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

std::string get_ost_path(const rawstd::URI& location) {
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

std::string get_object_spec_path(
    const std::string& ost_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".spec";

    return oss.str();
}

std::string
get_object_dat_path(const std::string& ost_path, const RawstdUUIDString& uuid) {
    std::ostringstream oss;

    oss << ost_path << "/" << uuid << ".dat";

    return oss.str();
}

void write_dat(
    const std::string& ost_path, const RawstorObjectSpec& spec,
    const RawstdUUID& id
) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(ost_path, uuid_string);

    int fd = open(dat_path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        if (ftruncate(fd, spec.size) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (fsync(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (const std::system_error& e) {
        close(fd);
        unlink(dat_path.c_str());
        throw;
    }
}

} // unnamed namespace

namespace rawstor {
namespace file {

Session::Session(rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(queue, location) {
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    run_in_worker(
        _queue,
        [location = location(), id, sp]() -> int {
            std::string ost_path = get_ost_path(location);
            if (mkdir(ost_path.c_str(), 0755) == -1) {
                if (errno == EEXIST) {
                    errno = 0;
                } else {
                    RAWSTD_THROW_ERRNO();
                }
            }

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string spec_path;
            spec_path = get_object_spec_path(ost_path, uuid_string);

            int fd = ::open(
                spec_path.c_str(), O_EXCL | O_CREAT | O_WRONLY,
                S_IRUSR | S_IWUSR
            );
            if (fd == -1) {
                RAWSTD_THROW_ERRNO();
            }

            try {
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

                write_meta_fd(fd, meta);

                if (::fsync(fd) == -1) {
                    RAWSTD_THROW_ERRNO();
                }

                write_dat(ost_path, sp, id);

                if (::close(fd) == -1) {
                    RAWSTD_THROW_ERRNO();
                }

                fsync_path(ost_path, O_RDONLY | O_DIRECTORY);
            } catch (...) {
                unlink(spec_path.c_str());
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
            std::string ost_path = get_ost_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string dat_path = get_object_dat_path(ost_path, uuid_string);
            if (unlink(dat_path.c_str()) == -1) {
                if (errno == ENOENT) {
                    errno = 0;
                } else {
                    RAWSTD_THROW_ERRNO();
                }
            }

            std::string spec_path = get_object_spec_path(ost_path, uuid_string);
            if (unlink(spec_path.c_str()) == -1) {
                if (errno == ENOENT) {
                    errno = 0;
                } else {
                    RAWSTD_THROW_ERRNO();
                }
            }

            return 0;
        },
        std::move(cb)
    );
}

void Session::meta(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    auto ret = std::make_shared<RawstorObjectMeta>();

    run_in_worker(
        _queue,
        [location = location(), id, ret]() -> int {
            std::string ost_path = get_ost_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string spec_path = get_object_spec_path(ost_path, uuid_string);

            int fd = ::open(spec_path.c_str(), O_RDONLY);
            if (fd == -1) {
                RAWSTD_THROW_ERRNO();
            }

            try {
                *ret = read_meta_fd(fd);

                if (::close(fd) == -1) {
                    RAWSTD_THROW_ERRNO();
                }
            } catch (...) {
                ::close(fd);
                throw;
            }

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
            std::string ost_path = get_ost_path(location);

            RawstdUUIDString uuid_string;
            rawstd_uuid_to_string(&id, &uuid_string);

            std::string spec_path = get_object_spec_path(ost_path, uuid_string);

            int fd = ::open(spec_path.c_str(), O_RDWR);
            if (fd == -1) {
                RAWSTD_THROW_ERRNO();
            }

            try {
                /* The stored size and placement identity are preserved. */
                RawstorObjectMeta stored = read_meta_fd(fd);
                RawstorObjectMeta next = meta;
                next.size = stored.size;
                next.member_kind = stored.member_kind;
                next.width = stored.width;
                memcpy(
                    next.volume_id, stored.volume_id, sizeof(next.volume_id)
                );
                next.logical_index = stored.logical_index;
                next.chunk_size = stored.chunk_size;
                next.snap_version = stored.snap_version;

                write_meta_fd(fd, next);

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

            return 0;
        },
        std::move(cb)
    );
}

void Session::set_object(Object* object, std::function<void(int)>&& cb) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    std::string ost_path = get_ost_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&object->id(), &id_string);

    /*
     * The path buffer is kept alive by the callback capture: io_uring reads
     * the string when the openat operation is executed, not when submitted.
     */
    auto dat_path =
        std::make_shared<std::string>(get_object_dat_path(ost_path, id_string));

    rawstd_info("Connecting to %s...\n", location().str().c_str());

    _queue.open(
        dat_path->c_str(), O_RDWR | O_NONBLOCK, 0,
        [this, dat_path, cb = std::move(cb)](int result) {
            if (result < 0) {
                cb(-result);
                return;
            }

            rawstd_info("fd %d: Connected\n", result);
            set_fd(result);
            cb(0);
        }
    );
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pread(fd(), buf, size, offset, std::move(cb));
}

void Session::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.preadv(fd(), iov, niov, offset, std::move(cb));
}

void Session::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pwrite(fd(), buf, size, offset, std::move(cb));
}

void Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd_debug(
        "%s(): fd = %d, size = %zu, offset = %jd\n", __FUNCTION__, fd(), size,
        (intmax_t)offset
    );

    _queue.pwritev(fd(), iov, niov, offset, std::move(cb));
}

} // namespace file
} // namespace rawstor
