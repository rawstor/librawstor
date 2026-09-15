#ifndef RAWSTOR_CLI_CREATE_H
#define RAWSTOR_CLI_CREATE_H

#include <rawstor.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// `chunk_size`/`width`/`failure_domain`/`stripe_width` are volume policy,
// meaningful only when `target`/`location` is mds:// -- 0 in each field
// means "use the documented default" (see struct RawstorObjectSpec), and
// all-zero altogether is silently ignored for a non-volume target.
int rawstor_cli_create(
    const char* target, uint64_t size, unsigned int mirrors,
    uint64_t chunk_size, uint8_t width, uint8_t failure_domain,
    uint64_t stripe_width
);

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size, unsigned int mirrors,
    uint64_t chunk_size, uint8_t width, uint8_t failure_domain,
    uint64_t stripe_width
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_CLI_CREATE_H
