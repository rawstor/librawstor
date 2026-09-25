#ifndef RAWSTOR_TARGET_PATH_HPP
#define RAWSTOR_TARGET_PATH_HPP

#include <rawstd/uuid.h>

#include <cstdint>
#include <string>

namespace rawstor {

// A target URI's own trailing path identity, in one of three shapes:
// - Physical, with a bound snapshot: `/<id>/<offset>/<snapshot_id>` --
//   offset always an explicit segment (even "0"), the convention
//   every internal builder in this codebase uses whenever it
//   addresses one chunk of a larger object.
// - Physical, live: `/<id>/<offset>` -- same convention, no bound
//   snapshot.
// - Logical: `/<id>[/<snapshot_id>]` -- no offset segment at all, implied
//   0. This is the shape a caller types by hand to name a plain
//   target's own bound snapshot -- there is no chunk-offset concept
//   to name at that level. A bare `/<id>`, with no snapshot either,
//   is this same shape with nothing bound.
//
// All three are really the same grammar read from the *end* (a
// target's own location can itself carry an arbitrary path, e.g.
// file:///a/b, so the identity can't be found any other way): if the
// last segment isn't UUID-shaped, it must be a hexadecimal chunk offset
// with a UUID id right before it -- the physical-live shape, no
// snapshot. If the last segment IS UUID-shaped, it's tentatively a
// trailing snapshot_id; check what precedes it: another UUID right
// before it makes this the logical shape (that UUID is the id, the
// last segment its bound snapshot); a valid hexadecimal offset followed
// by a UUID makes it the physical-with-snapshot shape instead. If
// neither precedes it, the last segment is not a snapshot at all --
// just a bare id. See parse_target_path()'s own comment in
// target_path.cpp for the exact algorithm. `segments` is how many
// trailing path segments this identity actually consumed (1, 2, or 3)
// -- callers that need the URI with the identity stripped back off (to
// recover the plain Location it was built under) call URI::parent()
// this many times, not just once.
struct TargetPath {
    RawstdUUID id;
    uint64_t offset;
    RawstdUUID snapshot_id;
    unsigned int segments;
};

// Parses a target's own trailing path identity (see TargetPath's own
// doc comment above) out of `path` -- a URI's own path (URI::path().str())
// or, for a caller with no real URI to hand (a bare cursor string, e.g.
// decode_token() in location.cpp), the identity's own path segments with
// no scheme/host in front of them at all: the grammar only ever looks at
// the path, so both are parsed identically. Throws EINVAL if the path's
// last segment (past any snapshot/offset segments) isn't a valid UUID,
// or an offset segment isn't a valid hexadecimal number.
TargetPath parse_target_path(const std::string& path);

} // namespace rawstor

#endif // RAWSTOR_TARGET_PATH_HPP
