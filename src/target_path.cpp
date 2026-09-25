#include "target_path.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>

#include <cstdlib>
#include <string>

#include <cerrno>

namespace {

// Whether `s` is a well-formed, non-negative hexadecimal number in full --
// shared by parse_target_path()'s two offset checks below (the last
// segment for the physical-live shape, the one before a trailing
// snapshot_id for the physical-with-snapshot shape). Hex, not decimal:
// every other numeric field this codebase persists or transmits alongside
// a chunk's own identity (meta_encode()'s own chunk_size, epoch, sync_id,
// ...) is already hex, so a human reading a target string, a backend's
// own physical path, or a persisted meta record side by side sees the
// same base everywhere instead of having to remember which fields are
// which.
bool parse_hex_offset(const std::string& s, uint64_t* out) {
    char* endptr = nullptr;
    errno = 0;
    unsigned long long parsed = strtoull(s.c_str(), &endptr, 16);
    if (errno != 0 || endptr == s.c_str() || *endptr != '\0') {
        return false;
    }
    *out = parsed;
    return true;
}

} // namespace

namespace rawstor {

// Finds a target's own trailing chunk identity in `path` (TargetPath's
// own doc comment, target_path.hpp): the path may carry an arbitrarily
// deep location prefix in front of it (e.g. /a/b/c/<id>), so the identity
// can't be found by counting segments from the front -- only by reading
// from the *end*. If the last segment isn't UUID-shaped, it must be a
// valid hexadecimal chunk offset with a UUID id right before it -- the
// physical-live shape, no snapshot. If the last segment IS UUID-shaped,
// it's tentatively a trailing snapshot_id; another UUID right before it
// makes this the logical shape instead (that UUID is the real id, the
// last segment its bound snapshot); a valid hexadecimal offset followed
// by a UUID makes it the physical-with-snapshot shape. If neither
// precedes it, the last segment isn't a snapshot at all -- just a bare
// id.
TargetPath parse_target_path(const std::string& path) {
    rawstd::URIPath uri_path(path);
    const std::string& last = uri_path.filename();

    // rawstd_uuid_from_string() writes into its output byte by byte as it
    // parses and can leave it partially (non-nil-ly) clobbered on a
    // failed attempt -- every candidate parse below lands in its own
    // local first, never straight into `ret`, so a rejected candidate
    // never leaks a bogus non-nil value into the final result.
    TargetPath ret{};
    RawstdUUID last_as_uuid;
    if (rawstd_uuid_from_string(&last_as_uuid, last.c_str()) == 0) {
        rawstd::URIPath dirname1(uri_path.dirname());
        const std::string& seg2 = dirname1.filename();

        RawstdUUID id2;
        if (rawstd_uuid_from_string(&id2, seg2.c_str()) == 0) {
            // Logical shape: <id>/<snapshot_id>.
            ret.id = id2;
            ret.offset = 0;
            ret.snapshot_id = last_as_uuid;
            ret.segments = 2;
            return ret;
        }

        uint64_t offset2 = 0;
        if (parse_hex_offset(seg2, &offset2)) {
            rawstd::URIPath dirname2(dirname1.dirname());
            RawstdUUID id3;
            if (rawstd_uuid_from_string(&id3, dirname2.filename().c_str()) ==
                0) {
                // Physical shape with a bound snapshot:
                // <id>/<offset>/<snapshot_id>.
                ret.id = id3;
                ret.offset = offset2;
                ret.snapshot_id = last_as_uuid;
                ret.segments = 3;
                return ret;
            }
        }

        // A lone trailing UUID with nothing recognizable behind it: a
        // bare id, no bound snapshot.
        ret.id = last_as_uuid;
        ret.offset = 0;
        ret.segments = 1;
        return ret;
    }

    // The physical-live shape: <id>/<offset>, no snapshot anywhere in
    // the path.
    uint64_t offset = 0;
    if (!parse_hex_offset(last, &offset)) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    rawstd::URIPath parent_path(uri_path.dirname());
    int res = rawstd_uuid_from_string(&ret.id, parent_path.filename().c_str());
    if (res < 0) {
        rawstd_error("Valid UUID expected\n");
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    ret.offset = offset;
    ret.segments = 2;
    return ret;
}

} // namespace rawstor
