#include "lvm_backend.hpp"

#include "blkdev_meta.hpp"
#include "opts.h"
#include "subprocess.hpp"

#include <nlohmann/json.hpp>

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/uuid.h>

#include <algorithm>
#include <cerrno>
#include <cinttypes>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <mutex>
#include <sstream>
#include <string>
#include <unordered_set>

#include <fcntl.h>

namespace {

// --config override passed to every lvcreate/lvremove/lvs/vgs invocation
// below, so this backend's behavior doesn't depend on the host's own
// lvm.conf.
//
// activation/udev_sync forces device-mapper's udev synchronization on
// (regardless of a --noudevsync passed by whoever else might invoke these
// tools) -- lvcreate/lvremove rely on the LV's device node having already
// appeared/disappeared under /dev by the time the command returns, which
// is only guaranteed when this is on.
//
// allocation/wipe_signatures_when_zeroing_new_lvs=0 skips lvcreate's own
// whole-LV scan for leftover filesystem signatures (and the confirmation
// prompt for wiping each one it finds, already answered by --yes below
// regardless) -- pure overhead here, since create() always zero-fills
// the whole LV itself right after (see below), which wipes any such
// signature along with everything else on the volume.
//
// report/time_format="%s" makes every *_time report field (lv_time, used
// by _cleanup_staging_lvs() below) a plain Unix timestamp instead of the
// default locale-formatted string, which is trivial to parse and compare
// against.
const char* const lvm_config =
    "activation{udev_sync=1 udev_rules=1} "
    "allocation{wipe_signatures_when_zeroing_new_lvs=0} "
    "report{time_format=\"%s\"}";

// Prefix of the LVM tag this backend stores native per-copy mirror
// metadata under (see src/blkdev_meta.hpp) -- e.g.
// "rawstor.meta=state=0:epoch=0:...".
const char* const rawstor_tag_prefix = "rawstor.meta=";

// Suffix a staging LV carries between lvcreate and the lvrename that
// reveals it under its real (UUID) name -- see Backend::create()'s own
// doc comment for why. Never a valid UUID string, so list()'s
// rawstd_uuid_from_string() already skips a staging LV on its own, with
// no dedicated filtering needed there.
const char* const staging_suffix = ".creating";

// _cleanup_staging_lvs() below only removes a "*.creating" LV at least
// this old: it's a per-VG, once-per-process, name-agnostic sweep (unlike
// the per-attempt random staging name create() itself now uses -- see
// its own doc comment -- this one can't tell a stale, crashed-process
// leftover apart from a live sibling's still-in-progress create() by
// name alone). Anything younger is presumed to still possibly be a live
// create() in progress and is left alone; a real orphan just waits for
// the next process that touches this VG.
constexpr long staging_min_age_seconds = 300;

// Guards Backend::_cleanup_staging_lvs() so the orphan sweep for a given
// VG runs at most once per process, regardless of how many Backend
// instances end up connected to it over time (one per Connection pool
// slot, plus reconnects) -- listing/removing the same (already-gone,
// after the first sweep) orphans repeatedly would be pure waste.
std::mutex swept_vgs_mutex;
std::unordered_set<std::string> swept_vgs;

std::string parse_vg_name(const rawstd::URI& location) {
    if (location.scheme() != "lvm") {
        rawstd_error("Unexpected URI scheme: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    if (location.host().empty()) {
        rawstd_error("VG name is empty in URI: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    const std::string& path = location.path().str();
    if (!path.empty() && path != "/") {
        rawstd_error("Unexpected path in URI: %s\n", location.str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }
    return location.host();
}

} // namespace

namespace rawstor {
namespace lvm {

Backend::Backend(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::blk::Backend(p, queue, location),
    _vg_name(parse_vg_name(location)) {
}

std::string Backend::_device_path_for_name(const std::string& name) const {
    std::ostringstream oss;
    oss << "/dev/" << _vg_name << "/" << name;
    return oss.str();
}

std::string Backend::_device_path(const RawstdUUID& id) const {
    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);
    return _device_path_for_name(uuid_str);
}

rawstd::Task<int> Backend::_open(const RawstdUUID& id) {
    std::string path = _device_path(id);

    // No O_NONBLOCK: io_uring does not need the fd to be non-blocking --
    // it handles blocking operations internally via io_wq worker threads.
    // O_NONBLOCK on a block device instead surfaces cache-miss reads as
    // -EAGAIN, which the pread/pwrite paths above don't retry. O_CLOEXEC
    // so this fd doesn't leak into the lvcreate/lvremove children forked
    // by create()/remove() below.
    int fd = co_await _queue.open(path.c_str(), O_RDWR | O_CLOEXEC, 0);
    co_return fd;
}

rawstd::Task<void> Backend::list(
    unsigned int limit, std::vector<RawstdUUID>& targets, RawstdUUID& token
) {
    co_await _cleanup_staging_lvs();

    RawstdUUID input_token = token;
    targets.clear();
    token = {};

    // GCC 13 ICEs (is_this_parameter) when a std::vector<std::string>
    // argument is brace-initialized directly at the call site of a nested
    // coroutine that's co_await-ed from within another coroutine -- naming
    // the vector first works around it.
    std::vector<std::string> list_argv = {
        "lvs", "--config", lvm_config, "--reportformat",     "json",
        "-o",  "lv_name",  "--select", "vg_name=" + _vg_name
    };
    std::string output;
    try {
        output =
            co_await rawstor::run_command_capture(_queue, std::move(list_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to list LVs in VG %s: %s\n", _vg_name.c_str(), e.what()
        );
        throw;
    }

    try {
        nlohmann::json parsed = nlohmann::json::parse(output);
        for (const auto& lv : parsed.at("report").at(0).at("lv")) {
            std::string name = lv.at("lv_name").get<std::string>();

            RawstdUUID uuid;
            if (rawstd_uuid_from_string(&uuid, name.c_str()) < 0) {
                continue;
            }
            targets.push_back(uuid);
        }
    } catch (const std::exception& e) {
        rawstd_error(
            "lvm: failed to parse lvs JSON output for VG %s: %s\n",
            _vg_name.c_str(), e.what()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    std::sort(
        targets.begin(), targets.end(),
        [](const RawstdUUID& lhs, const RawstdUUID& rhs) {
            return rawstd_uuid_cmp(&lhs, &rhs) < 0;
        }
    );

    targets.erase(
        targets.begin(), std::upper_bound(
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

    co_return;
}

rawstd::Task<void> Backend::_cleanup_staging_lvs() {
    {
        std::lock_guard<std::mutex> lock(swept_vgs_mutex);
        if (!swept_vgs.insert(_vg_name).second) {
            co_return; // Already swept this VG earlier in this process.
        }
    }

    std::vector<std::string> list_argv = {
        "lvs", "--config",        lvm_config, "--reportformat",     "json",
        "-o",  "lv_name,lv_time", "--select", "vg_name=" + _vg_name
    };
    std::string output;
    try {
        output =
            co_await rawstor::run_command_capture(_queue, std::move(list_argv));
    } catch (const std::system_error& e) {
        rawstd_warning(
            "lvm: failed to list LVs in VG %s while sweeping for orphaned "
            "staging LVs left over from a previous crash: %s\n",
            _vg_name.c_str(), e.what()
        );
        co_return;
    }

    long now = static_cast<long>(::time(nullptr));
    std::vector<std::string> orphans;
    try {
        nlohmann::json parsed = nlohmann::json::parse(output);
        for (const auto& lv : parsed.at("report").at(0).at("lv")) {
            std::string name = lv.at("lv_name").get<std::string>();
            if (!name.ends_with(staging_suffix)) {
                continue;
            }
            long created_at = std::stol(lv.at("lv_time").get<std::string>());
            if (now - created_at < staging_min_age_seconds) {
                // Too young to trust: this name-agnostic sweep can't tell
                // a genuine crashed-process leftover apart from a live
                // sibling's still-in-progress create() -- see
                // staging_min_age_seconds's own doc comment.
                continue;
            }
            orphans.push_back(std::move(name));
        }
    } catch (const std::exception& e) {
        rawstd_warning(
            "lvm: failed to parse lvs JSON output for VG %s while sweeping "
            "for orphaned staging LVs: %s\n",
            _vg_name.c_str(), e.what()
        );
        co_return;
    }

    for (const std::string& name : orphans) {
        rawstd_warning(
            "lvm: removing orphaned staging LV %s in VG %s, left over from "
            "an interrupted create()\n",
            name.c_str(), _vg_name.c_str()
        );
        std::vector<std::string> remove_argv = {
            "lvremove", "--config", lvm_config, "-f",
            _device_path_for_name(name)
        };
        try {
            co_await rawstor::run_command(_queue, std::move(remove_argv));
        } catch (const std::system_error& e) {
            rawstd_warning(
                "lvm: failed to remove orphaned staging LV %s in VG %s: "
                "%s\n",
                name.c_str(), _vg_name.c_str(), e.what()
            );
        }
    }
}

rawstd::Task<void>
Backend::create(const RawstdUUID& id, const RawstorObjectSpec& sp) {
    if (sp.size == 0) {
        rawstd_error("lvm: object size must be positive\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    RawstdUUIDString uuid_str;
    rawstd_uuid_to_string(&id, &uuid_str);
    std::string real_path = _device_path(id);

    // create() must behave like open(O_EXCL): retrying it against an id
    // a previous, unacknowledged attempt already fully created (lvcreate
    // + zero-fill + lvrename all succeeded, but the response never made
    // it back to the caller) needs to fail fast with EEXIST -- already
    // classified as permanent, never retried, by
    // Connection::_with_retry()'s is_permanent_backend_error(), and the
    // same convention file::Backend's own O_EXCL create() already
    // follows -- instead of redoing the whole lvcreate + zero-fill cycle
    // only to fail later at the rename step with a generic, retried-
    // pointlessly EIO.
    if (co_await _exists(real_path)) {
        rawstd_error(
            "lvm: LV %s already exists in VG %s\n", uuid_str, _vg_name.c_str()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EEXIST);
    }

    co_await _cleanup_staging_lvs();

    // Unique per *attempt*, not derived from `id` -- two concurrent
    // create() calls for the same id (e.g. a client that reconnected and
    // resent ALLOCATE while the server was still processing its first,
    // unacknowledged attempt) must never contend over the same staging
    // name. An earlier version of this derived the staging name from
    // `id` alone and self-healed a same-named leftover on the assumption
    // it could only be this id's own crashed attempt -- provably wrong
    // whenever a sibling attempt for the same id is legitimately still
    // running: each side's own "leftover cleanup" lvremove'd the other's
    // live, still-being-zeroed staging LV out from under it, observed
    // live (loopback lvm2 2.03.16) to cascade into both sides repeatedly
    // clobbering each other's replacement staging LV. A random UUID
    // makes that structurally impossible: nothing else ever guesses or
    // needs to reconstruct this name, since the rename below already has
    // it as a local variable.
    RawstdUUID staging_id;
    if (rawstd_uuid7_init(&staging_id) != 0) {
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
    RawstdUUIDString staging_uuid_str;
    rawstd_uuid_to_string(&staging_id, &staging_uuid_str);
    std::string staging_name = std::string(staging_uuid_str) + staging_suffix;
    std::string staging_path = _device_path_for_name(staging_name);

    // lvcreate rounds the size up to the VG extent size itself.
    char size_buf[32];
    snprintf(size_buf, sizeof(size_buf), "%" PRIu64 "b", sp.size);

    // A fresh copy starts with sync_id 0: it has never been part of an
    // established sync set (docs/mirroring.md). Set on the staging LV
    // itself, carried across by lvrename() below, so there is never a
    // window -- staged or revealed -- where the LV exists without one.
    RawstorObjectMeta initial{};
    initial.state = RAWSTOR_OBJECT_STATE_CLEAN;
    std::string tag =
        std::string(rawstor_tag_prefix) + blkdev_meta_encode(initial);

    rawstd_info(
        "lvm: creating LV %s in VG %s, size %s\n", uuid_str, _vg_name.c_str(),
        size_buf
    );

    // Created under a staging name and only lvrename()d to its real,
    // UUID name once it's fully zeroed below: lvcreate -Z (on by default)
    // only zeroes the first 4KiB of a new LV, for signature safety, not
    // the whole thing -- a thick LV's freshly allocated extents can
    // otherwise still hold whatever a previous LV in this VG left on
    // them. Revealing it under its real name only now means every access
    // path (set_object()/spec()/pread() -- not just list(), which
    // already skips a non-UUID name on its own) sees plain ENOENT until
    // zeroing has actually finished, instead of a still-partially-zeroed
    // device. It also survives this process crashing mid-fill: the LV
    // just sits there under its staging name, invisible and harmless,
    // until _cleanup_staging_lvs() above removes it.
    //
    // GCC 13 ICEs (build_special_member_call) when a std::vector<std::string>
    // argument is brace-initialized directly at the call site of a nested
    // coroutine that's co_await-ed from within another coroutine -- naming
    // the vector first works around it.
    std::vector<std::string> create_argv = {
        "lvcreate", "--config",   lvm_config, "--yes", "-L",    size_buf,
        "-n",       staging_name, "--addtag", tag,     _vg_name
    };
    try {
        co_await rawstor::run_command(_queue, std::move(create_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to create LV %s in VG %s: %s\n", uuid_str,
            _vg_name.c_str(), e.what()
        );
        throw;
    }

    // co_await isn't allowed inside a catch block, so every failure below
    // is only recorded here (as `error`/`eptr`); the rollback itself runs
    // afterwards, outside any handler.
    std::exception_ptr eptr;
    int error = 0;
    try {
        rawstd_info(
            "lvm: zeroing LV %s in VG %s...\n", staging_name.c_str(),
            _vg_name.c_str()
        );
        int fd =
            co_await _queue.open(staging_path.c_str(), O_RDWR | O_CLOEXEC, 0);

        std::exception_ptr zero_eptr;
        try {
            co_await _zero_fill(fd, 0, sp.size, /*unmap=*/false);
        } catch (...) {
            zero_eptr = std::current_exception();
        }
        co_await _queue.close(fd);
        if (zero_eptr) {
            std::rethrow_exception(zero_eptr);
        }

        std::vector<std::string> rename_argv = {"lvrename",   "--config",
                                                lvm_config,   _vg_name,
                                                staging_name, uuid_str};
        co_await rawstor::run_command(_queue, std::move(rename_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to initialize LV %s in VG %s: %s\n", uuid_str,
            _vg_name.c_str(), e.what()
        );
        error = e.code().value();
        eptr = std::current_exception();
    }

    if (eptr) {
        // Best-effort rollback: without this, a failure here (zeroing or
        // the rename) leaves the staging LV behind forever, invisible but
        // wasting VG space, until _cleanup_staging_lvs() next runs in some
        // future process (it only runs once per process, already spent
        // for this one at the top of this call).
        std::vector<std::string> rollback_argv = {
            "lvremove", "--config", lvm_config, "-f", staging_path
        };
        try {
            co_await rawstor::run_command(_queue, std::move(rollback_argv));
        } catch (const std::system_error& e2) {
            rawstd_warning(
                "lvm: failed to remove staging LV %s in VG %s after a "
                "failed create() (error %d): %s\n",
                staging_name.c_str(), _vg_name.c_str(), error, e2.what()
            );
        }
        std::rethrow_exception(eptr);
    }

    co_return;
}

rawstd::Task<void> Backend::remove(const RawstdUUID& id) {
    co_await _cleanup_staging_lvs();

    std::string path = _device_path(id);

    // Matches file::Backend::remove()'s own convention: a nonexistent LV
    // is ENOENT specifically (permanent -- never retried by
    // Connection::_with_retry()'s is_permanent_backend_error()), not the
    // generic, retryable EIO lvremove itself would produce for the same
    // case.
    if (!co_await _exists(path)) {
        rawstd_error("lvm: LV %s does not exist\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    rawstd_info("lvm: removing LV %s\n", path.c_str());

    std::vector<std::string> argv = {
        "lvremove", "--config", lvm_config, "-f", path
    };
    try {
        co_await rawstor::run_command(_queue, std::move(argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to remove LV %s: %s\n", path.c_str(), e.what()
        );
        throw;
    }

    co_return;
}

rawstd::Task<RawstorLocationInfo> Backend::info() {
    co_await _cleanup_staging_lvs();

    // See list()'s own comment on this GCC 13 ICE workaround.
    std::vector<std::string> info_argv = {
        "vgs", "--config",   lvm_config, "--reportformat",  "json",  "--units",
        "b",   "--nosuffix", "-o",       "vg_size,vg_free", _vg_name
    };
    std::string output;
    try {
        output =
            co_await rawstor::run_command_capture(_queue, std::move(info_argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to query VG %s: %s\n", _vg_name.c_str(), e.what()
        );
        throw;
    }

    uint64_t total;
    uint64_t free_bytes;
    try {
        nlohmann::json parsed = nlohmann::json::parse(output);
        const nlohmann::json& vg = parsed.at("report").at(0).at("vg").at(0);
        // --nosuffix still leaves vg_size/vg_free as JSON strings (LVM's
        // "json" report format quotes every field, numeric or not) rather
        // than native JSON numbers -- verified against lvm2 2.03.16.
        total = std::stoull(vg.at("vg_size").get<std::string>());
        free_bytes = std::stoull(vg.at("vg_free").get<std::string>());
    } catch (const std::exception& e) {
        rawstd_error(
            "lvm: failed to parse vgs JSON output for VG %s: %s\n",
            _vg_name.c_str(), e.what()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }

    RawstorLocationInfo ret{
        .used = total - free_bytes,
        .total = total,
    };

    co_return ret;
}

// Shared by meta()/set_state() below: the current comma-separated tag list
// on the LV at `path`, as reported by `lvs -o lv_tags`.
rawstd::Task<std::string> Backend::_lv_tags(const std::string& path) {
    std::vector<std::string> argv = {"lvs",      "--config",
                                     lvm_config, "--reportformat",
                                     "json",     "-o",
                                     "lv_tags",  path};
    std::string output;
    try {
        output = co_await rawstor::run_command_capture(_queue, std::move(argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to read tags of %s: %s\n", path.c_str(), e.what()
        );
        throw;
    }

    try {
        nlohmann::json parsed = nlohmann::json::parse(output);
        co_return parsed.at("report")
            .at(0)
            .at("lv")
            .at(0)
            .at("lv_tags")
            .get<std::string>();
    } catch (const std::exception& e) {
        rawstd_error(
            "lvm: failed to parse lvs JSON output for %s: %s\n", path.c_str(),
            e.what()
        );
        RAWSTD_THROW_SYSTEM_ERROR(EIO);
    }
}

rawstd::Task<RawstorObjectMeta> Backend::meta(const RawstdUUID& id) {
    std::string path = _device_path(id);
    std::string tags = co_await _lv_tags(path);
    std::string tag = blkdev_find_tag(tags, rawstor_tag_prefix);

    // An empty tag means one was never recorded: an LV created before
    // this feature, or by something else. Must not be trusted as CLEAN --
    // the caller treats any error here as "member stale, needs a resync"
    // (docs/mirroring.md, case F10).
    RawstorObjectMeta meta{};
    if (tag.empty() || !blkdev_meta_decode(tag, &meta)) {
        rawstd_error("lvm: no recorded mirror state on %s\n", path.c_str());
        RAWSTD_THROW_SYSTEM_ERROR(ENOENT);
    }

    // The tag never carries size (see blkdev_meta_encode()): merge in the
    // LV's real, current size the same way spec() reports it, rather than
    // trust a value that could go stale if the LV were ever resized
    // outside rawstor.
    RawstorObjectSpec sp = co_await spec(id);
    meta.size = sp.size;

    co_return meta;
}

rawstd::Task<void>
Backend::set_state(const RawstdUUID& id, const RawstorObjectMeta& meta) {
    std::string path = _device_path(id);
    std::string new_tag =
        std::string(rawstor_tag_prefix) + blkdev_meta_encode(meta);

    std::string tags = co_await _lv_tags(path);
    std::string old_tag = blkdev_find_tag(tags, rawstor_tag_prefix);

    std::vector<std::string> argv = {"lvchange", "--config", lvm_config};
    if (!old_tag.empty()) {
        argv.push_back("--deltag");
        argv.push_back(std::string(rawstor_tag_prefix) + old_tag);
    }
    argv.push_back("--addtag");
    argv.push_back(new_tag);
    argv.push_back(path);

    try {
        co_await rawstor::run_command(_queue, std::move(argv));
    } catch (const std::system_error& e) {
        rawstd_error(
            "lvm: failed to set mirror state on %s: %s\n", path.c_str(),
            e.what()
        );
        throw;
    }

    co_return;
}

} // namespace lvm
} // namespace rawstor
