#ifndef RAWSTOR_BLKDEV_META_HPP
#define RAWSTOR_BLKDEV_META_HPP

#include <rawstor/target.h>

#include <cstddef>
#include <string>

namespace rawstor {

// Bumped whenever blkdev_meta_encode()'s own field set changes -- carried
// as this format's own leading field (see below) rather than left for a
// caller to track separately, so every consumer (file/lvm/zfs backends)
// rejects a record from an incompatible version the same way.
constexpr unsigned int BLKDEV_META_FORMAT_VERSION = 1;

// Upper bound on blkdev_meta_encode()'s own return value, comfortably
// covering every field at its widest (a full 16 hex digits for each
// uint64_t one). A caller that needs a fixed-size record to write this
// into (file::Backend's own on-disk .meta file, which must stay exactly
// one size across rewrites -- see its own doc comment) can size that
// record to this constant instead of guessing.
constexpr size_t BLKDEV_META_MAX_SIZE = 256;

// Encodes a RawstorObjectSyncState (plus BLKDEV_META_FORMAT_VERSION) as a
// compact colon-separated string of hex fields, e.g.
// "version=1:state=0:epoch=0:sync_id=0:h0=0:h1=0:h2=0:h3=0". Used as the
// payload of a ZFS user property, (prefixed by the caller) an LVM tag, or
// (NUL-padded out to BLKDEV_META_MAX_SIZE) file::Backend's own on-disk
// .meta file: only characters valid in all three are used (no comma, no
// whitespace), and the result never exceeds BLKDEV_META_MAX_SIZE bytes.
std::string blkdev_meta_encode(const RawstorObjectSyncState& sync_state);

// Reverses blkdev_meta_encode(). Returns false and leaves *out untouched
// if value is not a well-formed encoding of the current
// BLKDEV_META_FORMAT_VERSION (including an empty string: the caller must
// not mistake "no value was ever recorded" for a valid record, and a
// record from a different format version, which this repo will never
// write again once it's bumped).
bool blkdev_meta_decode(const std::string& value, RawstorObjectSyncState* out);

} // namespace rawstor

#endif // RAWSTOR_BLKDEV_META_HPP
