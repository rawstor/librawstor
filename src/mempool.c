#include "mempool.h"

#include <sys/errno.h>
#include <stdlib.h>


struct RawstorMemPool {
    void *data;
    void **head;
    void **current;
    void **tail;
    size_t object_size;
};


RawstorMemPool* rawstor_mempool_create(size_t capacity, size_t object_size) {
    RawstorMemPool *mempool = malloc(sizeof(RawstorMemPool));
    if (mempool == NULL) {
        goto err_mempool;
    }

    mempool->data = calloc(capacity, object_size);
    if (mempool->data == NULL) {
        goto err_data;
    }

    mempool->head = calloc(capacity, sizeof(void*));
    if (mempool->head == NULL) {
        goto err_head;
    }

    for (size_t i = 0; i < capacity; ++i) {
        mempool->head[i] = mempool->data + i * object_size;
    }

    mempool->current = &mempool->head[0];
    mempool->tail = &mempool->head[capacity];
    mempool->object_size = object_size;

    return mempool;

err_head:
    free(mempool->data);
err_data:
    free(mempool);
err_mempool:
    return NULL;
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


size_t rawstor_mempool_capacity(RawstorMemPool *mempool) {
    return mempool->tail - mempool->head;
}


size_t rawstor_mempool_object_size(RawstorMemPool *mempool) {
    return mempool->object_size;
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
