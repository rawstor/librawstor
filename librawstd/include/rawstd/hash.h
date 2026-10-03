#ifndef RAWSTD_HASH_H
#define RAWSTD_HASH_H

#include <sys/uio.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rawstd_hash_scalar(const void* buf, size_t size);

/*
 * A well-mixed 64-bit hash (FNV-1a with MurmurHash3's fmix64 finalizer)
 * that is identical in every build, libxxhash or not. Meant for spreading
 * keys (placement, scheduling), not for checking data integrity.
 */
uint64_t rawstd_hash_stable(const void* buf, size_t size);

int rawstd_hash_vector(
    const struct iovec* iov, unsigned int niov, uint64_t* hash
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_HASH_H
