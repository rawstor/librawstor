#ifndef RAWSTORSTD_HASH_H
#define RAWSTORSTD_HASH_H

#include <sys/uio.h>

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

uint64_t rawstor_hash_scalar(void* buf, size_t size);

int rawstor_hash_vector(
    const struct iovec* iov, unsigned int niov, uint64_t* hash
);

#ifdef __cplusplus
}
#endif

#endif // RAWSTORSTD_HASH_H
