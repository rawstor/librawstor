#include "mempool.h"

#include <sys/errno.h>
#include <stdlib.h>


struct RawstorMemPool {
    void *data;
    void **head;
    void **current;
    void **tail;
    size_t count;
    size_t size;
};


RawstorMemPool* rawstor_mempool_create(size_t count, size_t size) {
    RawstorMemPool *mempool = malloc(sizeof(RawstorMemPool));
    if (mempool == NULL) {
        return NULL;
    }

    mempool->data = calloc(count, size);
    if (mempool->data == NULL) {
        free(mempool);
        return NULL;
    }

    mempool->head = calloc(count, sizeof(void*));
    if (mempool->head == NULL) {
        free(mempool->data);
        free(mempool);
        return NULL;
    }

    for (size_t i = 0; i < count; ++i) {
        mempool->head[i] = mempool->data + i * size;
    }

    mempool->current = &mempool->head[0];
    mempool->tail = &mempool->head[count];
    mempool->count = count;
    mempool->size = size;

    return mempool;
}


void rawstor_mempool_delete(RawstorMemPool *mempool) {
    free(mempool->head);
    free(mempool->data);
    free(mempool);
}


size_t rawstor_mempool_available(RawstorMemPool *mempool) {
    return mempool->tail - mempool->current;
}


size_t rawstor_mempool_allocated(RawstorMemPool *mempool) {
    return mempool->current - mempool->head;
}


size_t rawstor_mempool_size(RawstorMemPool *mempool) {
    return mempool->size;
}


void* rawstor_mempool_data(RawstorMemPool *mempool) {
    return mempool->data;
}


void* rawstor_mempool_alloc(RawstorMemPool *mempool) {
    return *(mempool->current++);
}


void rawstor_mempool_free(RawstorMemPool *mempool, void *ptr) {
    *(--mempool->current) = ptr;
}
