#include "pool.h"

#include <sys/errno.h>
#include <stdlib.h>


struct RawstorPool {
    void *data;
    void **index;
    void **head;
    void **tail;
    size_t count;
    size_t size;
};


RawstorPool* rawstor_pool_create(size_t count, size_t size) {
    RawstorPool *pool = malloc(sizeof(RawstorPool));
    if (pool == NULL) {
        return NULL;
    }

    pool->data = calloc(count, size);
    if (pool->data == NULL) {
        free(pool);
        return NULL;
    }

    pool->index = calloc(count, sizeof(void*));
    if (pool->index == NULL) {
        free(pool->data);
        free(pool);
        return NULL;
    }

    for (size_t i = 0; i < count; ++i) {
        pool->index[i] = pool->data + i * size;
    }

    pool->head = &pool->index[0];
    pool->tail = &pool->index[count];
    pool->count = count;
    pool->size = size;

    return pool;
}


void rawstor_pool_delete(RawstorPool *pool) {
    free(pool->index);
    free(pool->data);
    free(pool);
}


size_t rawstor_pool_count(RawstorPool *pool) {
    return pool->tail - pool->head;
}


size_t rawstor_pool_size(RawstorPool *pool) {
    return pool->size;
}


void* rawstor_pool_data(RawstorPool *pool) {
    return pool->data;
}


void* rawstor_pool_alloc(RawstorPool *pool) {
    return *(pool->head++);
}


void rawstor_pool_free(RawstorPool *pool, void *ptr) {
    *(--pool->head) = ptr;
}
