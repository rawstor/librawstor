#ifndef RAWSTOR_STD_HASH_H
#define RAWSTOR_STD_HASH_H

#include <sys/uio.h>

#include <stdint.h>


uint64_t rawstor_hash_scalar(void* buf, size_t size);

uint64_t rawstor_hash_vector(const struct iovec *iov, unsigned niov);


#endif // RAWSTOR_STD_HASH_H
