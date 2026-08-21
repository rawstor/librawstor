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
#include <cstdio>
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

// Pre-0.2.4 objects were stored as a pair of files: "<uuid>.dat" (raw
// content) and "<uuid>.spec" (a serialized RawstorObjectSpec). Since 0.2.4
// an object is a single bare "<uuid>" file whose size doubles as its spec.
std::string get_legacy_dat_path(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << ".dat";

    return oss.str();
}

std::string get_legacy_spec_path(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::ostringstream oss;

    oss << location_path << "/" << uuid << ".spec";

    return oss.str();
}

bool path_exists(const std::string& path) {
    try {
        struct stat st;
        if (stat(path.c_str(), &st) == -1) {
            RAWSTD_THROW_ERRNO();
        }
        return true;
    } catch (const std::system_error& e) {
        if (e.code().value() == ENOENT) {
            return false;
        }
        throw;
    }
}

bool path_unlink(const std::string& path) {
    try {
        if (unlink(path.c_str()) == -1) {
            RAWSTD_THROW_ERRNO();
        }
        return true;
    } catch (const std::system_error& e) {
        if (e.code().value() == ENOENT) {
            return false;
        }
        throw;
    }
}

// If the object still exists in the legacy ".dat"/".spec" form, renames the
// ".dat" file to the current bare-file target path and drops the ".spec"
// file. Also finishes an interrupted migration (bare file already present,
// stray ".spec" left behind). No-op if the object doesn't exist yet.
void migrate_legacy(
    const std::string& location_path, const RawstdUUIDString& uuid
) {
    std::string target_path = get_target_path(location_path, uuid);
    std::string legacy_spec_path = get_legacy_spec_path(location_path, uuid);

    if (path_exists(target_path)) {
        path_unlink(legacy_spec_path);
        return;
    }

    std::string legacy_dat_path = get_legacy_dat_path(location_path, uuid);
    if (!path_exists(legacy_dat_path)) {
        return;
    }

    if (rename(legacy_dat_path.c_str(), target_path.c_str()) == -1) {
        RAWSTD_THROW_ERRNO();
    }

    path_unlink(legacy_spec_path);
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

    migrate_legacy(location_path, id_string);

    std::string target_path = get_target_path(location_path, id_string);

    rawstd_info("Connecting to %s...\n", location().str().c_str());
    int fd = open(target_path.c_str(), O_RDWR | O_NONBLOCK);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
    rawstd_info("fd %d: Connected\n", fd);
    return fd;
}

rawstd::Task<void> Session::list(
    unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    RawstdUUID input_token = token;
    targets.clear();
    token = {};
    try {
        std::string location_path = get_location_path(location());

        for (const auto& entry :
             std::filesystem::directory_iterator(location_path)) {
            std::string extension = entry.path().extension().string();

            std::string filename;
            if (extension.empty()) {
                filename = entry.path().filename().string();
            } else if (extension == ".dat") {
                // Not-yet-migrated legacy object.
                filename = entry.path().stem().string();
            } else {
                // ".spec" (legacy) or anything else.
                continue;
            }

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
    if (!path_unlink(target_path)) {
        std::string legacy_dat_path =
            get_legacy_dat_path(location_path, uuid_string);
        if (unlink(legacy_dat_path.c_str()) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    }

    path_unlink(get_legacy_spec_path(location_path, uuid_string));

    co_return;
}

rawstd::Task<RawstorObjectSpec> Session::spec(const RawstdUUID& id) {
    std::string location_path = get_location_path(location());

    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&id, &uuid_string);

    migrate_legacy(location_path, uuid_string);

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
            std::string extension = entry.path().extension().string();
            if (!extension.empty() && extension != ".dat") {
                // ".spec" (legacy) or anything else.
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
