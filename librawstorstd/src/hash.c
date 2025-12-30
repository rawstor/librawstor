#include "rawstorstd/hash.h"

#include "config.h"

#ifdef RAWSTOR_WITH_LIBXXHASH
#include <xxhash.h>
#endif

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <stdint.h>

uint64_t rawstor_hash_scalar(void* buf, size_t length) {
#ifdef RAWSTOR_WITH_LIBXXHASH
    return XXH3_64bits(buf, length);
#else
    (void)(buf);
    (void)(length);
    return 0;
#endif
}

int rawstor_hash_vector(
    const struct iovec* iov, unsigned int niov, uint64_t* hash
) {
    int ret;

#ifdef RAWSTOR_WITH_LIBXXHASH
    // Allocate a state struct. Do not just use malloc() or new.
    XXH3_state_t* state = XXH3_createState();
    if (state == NULL) {
        ret = -ENOMEM;
        goto err_state;
    }
    // Reset the state to start a new hashing session.
    XXH3_64bits_reset(state);

    for (unsigned int i = 0; i < niov; ++i) {
        XXH3_64bits_update(state, iov[i].iov_base, iov[i].iov_len);
    }

    // Retrieve the finalized hash. This will not change the state.
    XXH64_hash_t result = XXH3_64bits_digest(state);
    // Free the state. Do not use free().
    XXH3_freeState(state);
    *hash = result;

    return 0;

err_state:
    return ret;

#else
    (void)(iov);
    (void)(niov);

    *hash = 0;

    return 0;
#endif
}
