#ifndef RAWSTORSTD_MEMPOOL_H
#define RAWSTORSTD_MEMPOOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorMemPool RawstorMemPool;

RawstorMemPool* rawstor_mempool_create(size_t capacity, size_t object_size);

void rawstor_mempool_delete(RawstorMemPool* mempool);

size_t rawstor_mempool_available(RawstorMemPool* mempool);

size_t rawstor_mempool_allocated(RawstorMemPool* mempool);

size_t rawstor_mempool_capacity(RawstorMemPool* mempool);

size_t rawstor_mempool_object_size(RawstorMemPool* mempool);

void* rawstor_mempool_data(RawstorMemPool* mempool);

void* rawstor_mempool_alloc(RawstorMemPool* mempool);

void rawstor_mempool_free(RawstorMemPool* mempool, void* ptr);

#ifdef __cplusplus
}
#endif

#endif // RAWSTORSTD_MEMPOOL_H
