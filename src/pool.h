#ifndef RAWSTOR_POOL_H
#define RAWSTOR_POOL_H


#include <stddef.h>


typedef struct RawstorPool RawstorPool;


RawstorPool* rawstor_pool_create(size_t count, size_t size);

void rawstor_pool_delete(RawstorPool *pool);

size_t rawstor_pool_count(RawstorPool *pool);

size_t rawstor_pool_size(RawstorPool *pool);

void* rawstor_pool_data(RawstorPool *pool);

void* rawstor_pool_alloc(RawstorPool *pool);

void rawstor_pool_free(RawstorPool *pool, void *ptr);


#endif // RAWSTOR_POOL_H
