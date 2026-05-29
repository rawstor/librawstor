#ifndef RAWSTD_HASH_H
#define RAWSTD_HASH_H

#include <sys/uio.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rawstd_hash_scalar(const void* buf, size_t size);

int rawstd_hash_vector(
    const struct iovec* iov, unsigned int niov, uint64_t* hash
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_HASH_H
