#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// `mirrors` (copies per chunk) is never optional -- 0 is rejected outright
// (struct RawstorObjectSpec's own doc comment): it must equal the
// target/location's own comma-separated entry count when there's more
// than one, or the caller's own chosen redundancy (1 for an ordinary
// single-copy object) otherwise. `chunk_size` splits size into
// ceil(size / chunk_size) chunks -- create-by-location
// (rawstor_location_create()) does the splitting itself (target.cpp's
// Location::create()); create-by-target needs a hand-built, multi-offset
// TARGET naming them instead. `failure_domain`/`stripe_width` are object
// policy meaningful only when `target`/`location` is mds:// -- 0 in each
// means "use the documented default" (see struct RawstorObjectSpec),
// silently ignored otherwise.
int rawstor_cli_create(
    const char* target, uint64_t size, uint64_t chunk_size,
    unsigned int mirrors, unsigned int failure_domain, uint64_t stripe_width
);

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size, uint64_t chunk_size,
    unsigned int mirrors, unsigned int failure_domain, uint64_t stripe_width
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_H
