#include "lvm_session.hpp"

#include "blkdev_meta.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace {

const char* rawstor_tag_prefix = "rawstor.meta=";

} // namespace

namespace rawstor {
namespace lvm {

static std::string parse_vg_path(const rawstd::URI& location) {
    if (location.scheme() != "lvm") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!location.host().empty()) {
        rawstd_error("Empty host expected: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::string path = location.path().str();
    if (path.empty() || path == "/") {
        rawstd_error("VG path is empty in URI: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return path;
}

static std::string basename_of(const std::string& path) {
    size_t pos = path.rfind('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    BlkdevSession(p, queue, location),
    _vg_path(parse_vg_path(location)),
    _vg_name(basename_of(_vg_path)) {
}

std::string Session::device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << _vg_path << "/" << uuid_str;
    return oss.str();
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    char size_buf[64];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64 "b", sp.size);

    /*
     * A fresh copy starts with sync_id 0: it has never been part of an
     * established sync set (see docs/mirroring.md). Setting the tag in the
     * same command as creation means there is never a window where the LV
     * exists without one.
     */
    RawstorObjectMeta initial{};
    initial.state = RAWSTOR_OBJECT_STATE_CLEAN;
    std::string tag =
        std::string(rawstor_tag_prefix) + blkdev_meta_encode(initial);

    rawstd_info(
        "lvm: creating LV %s in VG %s, size %s\n", uuid_str, _vg_name.c_str(),
        size_buf
    );

    run_async(
        {"lvcreate", "--yes", "-L", size_buf, "-n", uuid_str, "--addtag", tag,
         _vg_name},
        device_path(id),
        [name = std::string(uuid_str), vg = _vg_name,
         cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "lvm: failed to create LV %s in VG %s: %s\n", name.c_str(),
                    vg.c_str(), strerror(error)
                );
            }
            cb(error);
        }
    );
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    /* lvremove removes the tag along with the LV. */
    std::string path = device_path(id);

    rawstd_info("lvm: removing LV %s\n", path.c_str());

    run_async(
        {"lvremove", "-f", path}, "",
        [path, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "lvm: failed to remove LV %s: %s\n", path.c_str(),
                    strerror(error)
                );
            }
            cb(error);
        }
    );
}

void Session::_meta_identity(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    std::string path = device_path(id);

    run_async_capture(
        {"lvs", "-o", "lv_tags", "--noheadings", path},
        [path, cb = std::move(cb)](std::string output, int error) mutable {
            if (error) {
                rawstd_error(
                    "lvm: failed to read tags of %s: %s\n", path.c_str(),
                    strerror(error)
                );
                cb({}, error);
                return;
            }

            std::string tag = blkdev_find_tag(output, rawstor_tag_prefix);

            /*
             * An empty tag means one was never recorded: an LV created
             * before this feature, or by something else. Must not be
             * trusted as CLEAN — the caller treats any error here as
             * "member stale, needs a resync" (docs/mirroring.md, case F10).
             */
            RawstorObjectMeta meta{};
            if (tag.empty() || !blkdev_meta_decode(tag, &meta)) {
                cb({}, ENOENT);
                return;
            }

            cb(meta, 0);
        }
    );
}

void Session::set_state(
    const RawstdUUID& id, const RawstorObjectMeta& meta,
    std::function<void(int)>&& cb
) {
    std::string path = device_path(id);
    std::string new_tag =
        std::string(rawstor_tag_prefix) + blkdev_meta_encode(meta);

    run_async_capture(
        {"lvs", "-o", "lv_tags", "--noheadings", path},
        [this, path, new_tag,
         cb = std::move(cb)](std::string output, int error) mutable {
            if (error) {
                rawstd_error(
                    "lvm: failed to read tags of %s: %s\n", path.c_str(),
                    strerror(error)
                );
                cb(error);
                return;
            }

            std::vector<std::string> cmd = {"lvchange"};

            std::string old_tag = blkdev_find_tag(output, rawstor_tag_prefix);
            if (!old_tag.empty()) {
                cmd.push_back("--deltag");
                cmd.push_back(std::string(rawstor_tag_prefix) + old_tag);
            }
            cmd.push_back("--addtag");
            cmd.push_back(new_tag);
            cmd.push_back(path);

            run_async(
                std::move(cmd), "",
                [path, cb = std::move(cb)](int error) mutable {
                    if (error != 0) {
                        rawstd_error(
                            "lvm: failed to set mirror state on %s: %s\n",
                            path.c_str(), strerror(error)
                        );
                    }
                    cb(error);
                }
            );
        }
    );
}

} // namespace lvm
} // namespace rawstor
