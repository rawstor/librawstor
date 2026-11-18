#ifndef RAWSTOR_IMAGE_HPP
#define RAWSTOR_IMAGE_HPP

#include "target.hpp"

#include <rawstor/target.h>

#include <string>

#include <sys/types.h>

namespace rawstor {

// Creates `destination` and fills it from the file `path`, or from `source`,
// an object or a version of one: the work behind rawstor_target_create_from_
// file()/_target() and rawstor_location_create_from_file()/_target(). `cb` is
// called as those functions document. Returns 0 once started, or a negative
// errno, in which case `cb` is never called.
int image_create_from_file(
    RawIOQueue* queue, Target destination, const RawstorObjectSpec& spec,
    const std::string& path, int (*cb)(ssize_t result, void* data), void* data
) noexcept;

int image_create_from_target(
    RawIOQueue* queue, Target destination, const RawstorObjectSpec& spec,
    Target source, int (*cb)(ssize_t result, void* data), void* data
) noexcept;

} // namespace rawstor

#endif // RAWSTOR_IMAGE_HPP
