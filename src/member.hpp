#ifndef RAWSTOR_MEMBER_HPP
#define RAWSTOR_MEMBER_HPP

#include <rawstor/target.h>

namespace rawstor {
// An optional witness occupies the last location beyond the data width.
inline bool
has_witness(const RawstorObjectSpec& spec, size_t members) noexcept {
    return members == spec.width + 1;
}

} // namespace rawstor
#endif
