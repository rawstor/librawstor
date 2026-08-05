#include "file_session.hpp"

#include "object.hpp"
#include "opts.h"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <cerrno>
#include <cstdio>
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

std::string get_object_spec_path(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << ".spec";

    return oss.str();
}

std::string get_object_dat_path(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << ".dat";

    return oss.str();
}

void write_dat(
    const std::string& location_path, const RawstorObjectSpec& spec,
    const RawstdUUID& id
) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(location_path, uuid_string);

    int fd = open(dat_path.c_str(), O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        if (ftruncate(fd, spec.size) == -1) {
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

int Session::_connect(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);
    std::string dat_path = get_object_dat_path(location_path, id_string);

    rawstd_info("Connecting to %s...\n", location().str().c_str());
    int fd = open(dat_path.c_str(), O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
    rawstd_info("fd %d: Connected\n", fd);
    return fd;
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
            if (entry.path().extension().string() != ".dat") {
                continue;
            }

            std::string filename = entry.path().stem().string();

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

    std::string spec_path;
    spec_path = get_object_spec_path(location_path, uuid_string);

    int fd = ::open(
        spec_path.c_str(), O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR
    );
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        ssize_t res = ::write(fd, &sp, sizeof(sp));
        if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        write_dat(location_path, sp, id);

        if (::close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        unlink(spec_path.c_str());
        ::close(fd);
        throw;
    }

    cb(0);
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string dat_path = get_object_dat_path(location_path, uuid_string);
    if (unlink(dat_path.c_str()) == -1) {
        RAWSTD_THROW_ERRNO();
    }

    std::string spec_path = get_object_spec_path(location_path, uuid_string);
    if (unlink(spec_path.c_str()) == -1) {
        RAWSTD_THROW_ERRNO();
    }

    cb(0);
}

void Session::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string spec_path = get_object_spec_path(location_path, uuid_string);

    int fd = ::open(spec_path.c_str(), O_RDONLY);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    RawstorObjectSpec ret;
    try {
        ssize_t rval = ::read(fd, &ret, sizeof(ret));
        if (rval == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (::close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        ::close(fd);
        throw;
    }

    cb(ret, 0);
}

void Session::location_info(
    std::function<void(const RawstorLocationInfo&, int)>&& cb
) {
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
            if (entry.path().extension().string() != ".dat") {
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

void Session::set_object(Object* object) {
    if (fd() != -1) {
        throw std::runtime_error("Object already set");
    }

    int fd = _connect(object->id());
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    set_fd(fd);
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
