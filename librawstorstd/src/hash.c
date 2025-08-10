#include "rawstorstd/hash.h"

#include <xxhash.h>

#include <sys/uio.h>

#include <assert.h>
#include <stdint.h>


uint64_t rawstor_hash_scalar(void* buf, size_t length) {
    return XXH3_64bits(buf, length);
}


uint64_t rawstor_hash_vector(const struct iovec *iovecs, unsigned nr_vecs) {
    // Allocate a state struct. Do not just use malloc() or new.
    XXH3_state_t* state = XXH3_createState();
    assert(state != NULL && "Out of memory!");
    // Reset the state to start a new hashing session.
    XXH3_64bits_reset(state);

    for (unsigned i = 0; i < nr_vecs; i++) {
        XXH3_64bits_update(state,
        iovecs[i].iov_base,
        iovecs[i].iov_len);
    }

    // Retrieve the finalized hash. This will not change the state.
    XXH64_hash_t result = XXH3_64bits_digest(state);
    // Free the state. Do not use free().
    XXH3_freeState(state);
    return result;
}
