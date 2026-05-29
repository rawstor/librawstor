#ifndef RAWSTD_MEMPOOL_H
#define RAWSTD_MEMPOOL_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstdMemPool RawstdMemPool;

RawstdMemPool* rawstd_mempool_create(size_t capacity, size_t object_size);

void rawstd_mempool_delete(RawstdMemPool* mempool);

size_t rawstd_mempool_available(RawstdMemPool* mempool);

size_t rawstd_mempool_allocated(RawstdMemPool* mempool);

size_t rawstd_mempool_capacity(RawstdMemPool* mempool);

size_t rawstd_mempool_object_size(RawstdMemPool* mempool);

void* rawstd_mempool_data(RawstdMemPool* mempool);

void* rawstd_mempool_alloc(RawstdMemPool* mempool);

void rawstd_mempool_free(RawstdMemPool* mempool, void* ptr);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_MEMPOOL_H
