#include "pool.h"

#include <sys/errno.h>
#include <stdlib.h>


struct RawstorPool {
    void *data;
    void **head;
    void **current;
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

    pool->head = calloc(count, sizeof(void*));
    if (pool->head == NULL) {
        free(pool->data);
        free(pool);
        return NULL;
    }

    for (size_t i = 0; i < count; ++i) {
        pool->head[i] = pool->data + i * size;
    }

    pool->current = &pool->head[0];
    pool->tail = &pool->head[count];
    pool->count = count;
    pool->size = size;

    return pool;
}


void rawstor_pool_delete(RawstorPool *pool) {
    free(pool->head);
    free(pool->data);
    free(pool);
}


size_t rawstor_pool_available(RawstorPool *pool) {
    return pool->tail - pool->current;
}


size_t rawstor_pool_allocated(RawstorPool *pool) {
    return pool->current - pool->head;
}


size_t rawstor_pool_size(RawstorPool *pool) {
    return pool->size;
}


void* rawstor_pool_data(RawstorPool *pool) {
    return pool->data;
}


void* rawstor_pool_alloc(RawstorPool *pool) {
    return *(pool->current++);
}


void rawstor_pool_free(RawstorPool *pool, void *ptr) {
    *(--pool->current) = ptr;
}
