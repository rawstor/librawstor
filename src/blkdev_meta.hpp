#ifndef RAWSTOR_BLKDEV_META_HPP
#define RAWSTOR_BLKDEV_META_HPP

#include <rawstor/target.h>

#include <string>

namespace rawstor {

// Encodes the mirror consistency state (state/epoch/sync_id/history) of a
// RawstorObjectMeta as a compact colon-separated string of hex fields, e.g.
// "state=0:epoch=0:sync_id=0:h0=0:h1=0:h2=0:h3=0". Used as the payload of a
// ZFS user property or (prefixed by the caller) an LVM tag: only characters
// valid in both are used (no comma, no whitespace).
std::string blkdev_meta_encode(const RawstorObjectMeta& meta);

// Reverses blkdev_meta_encode(). Returns false and leaves *out untouched if
// value is not a well-formed encoding (including an empty string: the
// caller must not mistake "no value was ever recorded" for a valid
// record).
bool blkdev_meta_decode(const std::string& value, RawstorObjectMeta* out);

// Finds a tag with the given prefix among a comma-separated LVM tag list
// (as returned by `lvs -o lv_tags`) and returns the substring after the
// prefix, up to the next comma or the end of the list. Returns an empty
// string if no tag with that prefix is present.
std::string
blkdev_find_tag(const std::string& tag_list, const std::string& prefix);

} // namespace rawstor

#endif // RAWSTOR_BLKDEV_META_HPP
