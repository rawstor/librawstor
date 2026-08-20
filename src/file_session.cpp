#include "file_session.hpp"

#include "opts.h"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

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

} // unnamed namespace

namespace rawstor {
namespace file {

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Session(p, queue, location) {
}

int Session::_connect(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString id_string;
    rawstd_uuid_to_string(&id, &id_string);

    std::string target_path = get_target_path(location_path, id_string);

    rawstd_info("Connecting to %s...\n", location().str().c_str());
    int fd = open(target_path.c_str(), O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
    rawstd_info("fd %d: Connected\n", fd);
    return fd;
}

rawstd::Task<std::vector<RawstdUUID>> Session::list(
    unsigned int limit, const RawstdUUID& token, RawstdUUID& next_token
) {
    std::vector<RawstdUUID> ret_uuids;
    next_token = {};
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
            next_token = ret_uuids.back();
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

    co_return ret_uuids;
}

rawstd::Task<void>
Session::create(const RawstdUUID& id, const RawstorObjectSpec& sp) {
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
        target_path.c_str(), O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR
    );
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        if (ftruncate(fd, sp.size) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (::close(fd) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        unlink(target_path.c_str());
        ::close(fd);
        throw;
    }

    co_return;
}

rawstd::Task<void> Session::remove(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);
    if (unlink(target_path.c_str()) == -1) {
        RAWSTD_THROW_ERRNO();
    }

    co_return;
}

rawstd::Task<RawstorObjectSpec> Session::spec(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    std::string target_path = get_target_path(location_path, uuid_string);

    RawstorObjectSpec ret{
        .size = std::filesystem::file_size(target_path),
    };

    co_return ret;
}

rawstd::Task<RawstorLocationInfo> Session::info() {
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
