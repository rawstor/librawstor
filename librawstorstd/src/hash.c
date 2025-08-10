#include "rawstorstd/hash.h"

#include "config.h"

#ifdef WITH_LIBXXHASH
#include <xxhash.h>
#endif

#include <sys/uio.h>

#include <assert.h>
#include <stdint.h>


uint64_t rawstor_hash_scalar(void* buf, size_t length) {
#ifdef WITH_LIBXXHASH
    return XXH3_64bits(buf, length);
#else
    (void)(buf);
    (void)(length);
    return 0;
#endif
}


uint64_t rawstor_hash_vector(const struct iovec *iov, unsigned niov) {
#ifdef WITH_LIBXXHASH
    // Allocate a state struct. Do not just use malloc() or new.
    XXH3_state_t* state = XXH3_createState();
    assert(state != NULL && "Out of memory!");
    // Reset the state to start a new hashing session.
    XXH3_64bits_reset(state);

    for (unsigned i = 0; i < niov; i++) {
        XXH3_64bits_update(state,
        iov[i].iov_base,
        iov[i].iov_len);
    }

    // Retrieve the finalized hash. This will not change the state.
    XXH64_hash_t result = XXH3_64bits_digest(state);
    // Free the state. Do not use free().
    XXH3_freeState(state);
    return result;
#else
    (void)(iov);
    (void)(niov);
    return 0;
#endif
}
