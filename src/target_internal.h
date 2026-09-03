#ifndef RAWSTOR_TARGET_INTERNAL_H
#define RAWSTOR_TARGET_INTERNAL_H

#include <rawstor/target.h>

#ifdef __cplusplus
extern "C" {
#endif

// Internal to this repository: not part of the installed public API (not
// listed in src/Makefile.am's librawstor_la_HEADERS, so `make install`
// never ships this header). Used by rawstor-ost (ost/src/client.cpp) to
// relay an incoming wire SET_STATE command to every location it locally
// serves for a UUID, and by this project's own tests to set up mirror
// consistency scenarios. Manually driving mirror consistency state from
// outside the library is unsafe for an application to do -- there is no
// supported general-purpose use case for this call, which is why it isn't
// declared alongside rawstor_target_spec()/rawstor_target_meta() in
// <rawstor/target.h>.
int rawstor_target_set_sync_state(
    RawIOQueue* queue, const char* target,
    const struct RawstorObjectSyncState* sync_state,
    int (*cb)(ssize_t result, void* data), void* data
) RAWSTOR_NOEXCEPT;

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_TARGET_INTERNAL_H
