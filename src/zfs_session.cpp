#include "zfs_session.hpp"

#include "blkdev_meta.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <sstream>
#include <string>

namespace {

const char* rawstor_property = "rawstor:meta";

std::string
dataset_of(const std::string& parent_dataset, const RawstdUUID& id) {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);
    return parent_dataset + "/" + uuid_str;
}

std::string snapshot_of(
    const std::string& parent_dataset, const RawstdUUID& id, uint64_t snap_id
) {
    std::ostringstream oss;
    oss << dataset_of(parent_dataset, id) << "@s" << snap_id;
    return oss.str();
}

} // namespace

namespace rawstor {
namespace zfs {

static std::string parse_parent_dataset(const rawstd::URI& location) {
    if (location.scheme() != "zfs") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (!location.host().empty()) {
        rawstd_error("Empty host expected: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    std::string path = location.path().str();
    if (path.empty() || path == "/") {
        rawstd_error(
            "Parent dataset is empty in URI: %s\n", location.str().c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    /* Strip leading slash: /tank/rawstor → tank/rawstor */
    if (path.front() == '/') {
        path = path.substr(1);
    }
    return path;
}

Session::Session(rawio::Queue& queue, const rawstd::URI& location) :
    BlkdevSession(queue, location),
    _parent_dataset(parse_parent_dataset(location)) {
}

std::string Session::device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);

    std::ostringstream oss;
    oss << "/dev/zvol/" << _parent_dataset << "/" << uuid_str;
    return oss.str();
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& sp,
    std::function<void(int)>&& cb
) {
    std::string dataset = dataset_of(_parent_dataset, id);

    char size_buf[64];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64, sp.size);

    /*
     * A fresh copy starts with sync_id 0: it has never been part of an
     * established sync set (see docs/mirroring.md). Setting the property
     * in the same command as creation means there is never a window where
     * the zvol exists without one.
     */
    RawstorObjectMeta initial{};
    initial.state = RAWSTOR_OBJECT_STATE_CLEAN;
    initial.member_kind = sp.member_kind;
    initial.width = sp.width;
    memcpy(initial.volume_id, sp.volume_id, sizeof(initial.volume_id));
    initial.logical_index = sp.logical_index;
    initial.chunk_size = sp.chunk_size;
    initial.snap_version = sp.snap_version;
    std::string prop =
        std::string(rawstor_property) + "=" + blkdev_meta_encode(initial);

    rawstd_info(
        "zfs: creating zvol %s, size %s bytes\n", dataset.c_str(), size_buf
    );

    run_async(
        {"zfs", "create", "-V", size_buf, "-o", prop, dataset}, device_path(id),
        [dataset, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "zfs: failed to create zvol %s: %s\n", dataset.c_str(),
                    strerror(error)
                );
            }
            cb(error);
        }
    );
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    /* zfs destroy removes the property along with the dataset. */
    std::string dataset = dataset_of(_parent_dataset, id);

    rawstd_info("zfs: destroying zvol %s\n", dataset.c_str());

    run_async(
        {"zfs", "destroy", dataset}, "",
        [dataset, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "zfs: failed to destroy zvol %s: %s\n", dataset.c_str(),
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
    std::string dataset = dataset_of(_parent_dataset, id);

    run_async_capture(
        {"zfs", "get", "-H", "-o", "value", rawstor_property, dataset},
        [dataset, cb = std::move(cb)](std::string output, int error) mutable {
            if (error) {
                rawstd_error(
                    "zfs: failed to read mirror state of %s: %s\n",
                    dataset.c_str(), strerror(error)
                );
                cb({}, error);
                return;
            }

            while (!output.empty() &&
                   (output.back() == '\n' || output.back() == '\r')) {
                output.pop_back();
            }

            /*
             * "-" means the property was never set: a zvol created before
             * this feature, or by something else. Must not be trusted as
             * CLEAN — the caller treats any error here as "member stale,
             * needs a resync" (docs/mirroring.md, case F10).
             */
            RawstorObjectMeta meta{};
            if (output.empty() || output == "-" ||
                !blkdev_meta_decode(output, &meta)) {
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
    std::string dataset = dataset_of(_parent_dataset, id);

    /* The stored placement identity is preserved: read-merge-write. */
    run_async_capture(
        {"zfs", "get", "-H", "-o", "value", rawstor_property, dataset},
        [this, dataset, meta,
         cb = std::move(cb)](std::string output, int error) mutable {
            if (error) {
                rawstd_error(
                    "zfs: failed to read mirror state of %s: %s\n",
                    dataset.c_str(), strerror(error)
                );
                cb(error);
                return;
            }

            RawstorObjectMeta next = meta;
            RawstorObjectMeta stored{};
            if (blkdev_meta_decode(output, &stored)) {
                blkdev_meta_merge_identity(&next, stored);
            }
            std::string prop =
                std::string(rawstor_property) + "=" + blkdev_meta_encode(next);

            run_async(
                {"zfs", "set", prop, dataset}, "",
                [dataset, cb = std::move(cb)](int error) mutable {
                    if (error != 0) {
                        rawstd_error(
                            "zfs: failed to set mirror state on %s: %s\n",
                            dataset.c_str(), strerror(error)
                        );
                    }
                    cb(error);
                }
            );
        }
    );
}

void Session::list(
    std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
) {
    /* -H = no header, tab-separated; -p = raw byte counts. */
    run_async_capture(
        {"zfs", "list", "-Hp", "-t", "volume", "-d", "1", "-o",
         "name,volsize," + std::string(rawstor_property), _parent_dataset},
        [parent = _parent_dataset,
         cb = std::move(cb)](std::string output, int error) mutable {
            if (error) {
                rawstd_error(
                    "zfs: failed to list zvols of %s: %s\n", parent.c_str(),
                    strerror(error)
                );
                cb({}, error);
                return;
            }

            std::vector<RawstorObjectListEntry> entries;

            std::istringstream iss(output);
            std::string line;
            while (std::getline(iss, line)) {
                size_t name_end = line.find('\t');
                size_t size_end = name_end == line.npos
                                      ? line.npos
                                      : line.find('\t', name_end + 1);
                if (size_end == line.npos) {
                    continue;
                }

                std::string name = line.substr(0, name_end);
                if (name.compare(0, parent.size() + 1, parent + "/") != 0) {
                    continue;
                }
                name.erase(0, parent.size() + 1);

                RawstorObjectListEntry entry{};
                RawstdUUID id;
                /* zvols not named after an object UUID are not ours. */
                if (rawstd_uuid_from_string(&id, name.c_str()) != 0) {
                    continue;
                }
                memcpy(entry.obj_id, id.bytes, sizeof(entry.obj_id));

                std::string value = line.substr(size_end + 1);
                while (!value.empty() &&
                       (value.back() == '\n' || value.back() == '\r')) {
                    value.pop_back();
                }
                if (value.empty() || value == "-" ||
                    !blkdev_meta_decode(value, &entry.meta)) {
                    rawstd_error(
                        "zfs: %s/%s: no valid mirror state property, "
                        "skipped\n",
                        parent.c_str(), name.c_str()
                    );
                    continue;
                }

                entry.meta.size =
                    strtoull(line.c_str() + name_end + 1, nullptr, 10);

                entries.push_back(entry);
            }

            cb(std::move(entries), 0);
        }
    );
}

void Session::snapshot(
    const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
) {
    std::string dataset = dataset_of(_parent_dataset, id);
    std::string snapshot = snapshot_of(_parent_dataset, id, snap_id);

    rawstd_info("zfs: creating snapshot %s\n", snapshot.c_str());

    run_async(
        {"zfs", "snapshot", snapshot}, "",
        [this, dataset, snapshot, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "zfs: failed to create snapshot %s: %s\n", snapshot.c_str(),
                    strerror(error)
                );
                cb(error);
                return;
            }

            /*
             * The snapshot read path opens
             * /dev/zvol/<parent>/<uuid>@s<id>, which exists only with
             * snapdev=visible on the origin. Set it with the snapshot, so
             * every snapshot that exists is also openable — one mechanism,
             * old zvols included.
             */
            run_async(
                {"zfs", "set", "snapdev=visible", dataset}, "",
                [dataset, cb = std::move(cb)](int error) mutable {
                    if (error != 0) {
                        rawstd_error(
                            "zfs: failed to set snapdev=visible on %s: %s\n",
                            dataset.c_str(), strerror(error)
                        );
                    }
                    cb(error);
                }
            );
        }
    );
}

void Session::snap_remove(
    const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
) {
    std::string snapshot = snapshot_of(_parent_dataset, id, snap_id);

    rawstd_info("zfs: destroying snapshot %s\n", snapshot.c_str());

    run_async(
        {"zfs", "destroy", snapshot}, "",
        [snapshot, cb = std::move(cb)](int error) mutable {
            if (error != 0) {
                rawstd_error(
                    "zfs: failed to destroy snapshot %s: %s\n",
                    snapshot.c_str(), strerror(error)
                );
            }
            cb(error);
        }
    );
}

} // namespace zfs
} // namespace rawstor
