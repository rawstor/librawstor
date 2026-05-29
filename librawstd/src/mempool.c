#include "rawstd/mempool.h"

#include <errno.h>

#include <stdlib.h>

struct RawstdMemPool {
    void* data;
    void** head;
    void** current;
    void** tail;
    size_t object_size;
};

RawstdMemPool* rawstd_mempool_create(size_t capacity, size_t object_size) {
    RawstdMemPool* mempool = malloc(sizeof(RawstdMemPool));
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

void rawstd_mempool_delete(RawstdMemPool* mempool) {
    free(mempool->head);
    free(mempool->data);
    free(mempool);
}

size_t rawstd_mempool_available(RawstdMemPool* mempool) {
    return mempool->tail - mempool->current;
}

size_t rawstd_mempool_allocated(RawstdMemPool* mempool) {
    return mempool->current - mempool->head;
}

size_t rawstd_mempool_capacity(RawstdMemPool* mempool) {
    return mempool->tail - mempool->head;
}

size_t rawstd_mempool_object_size(RawstdMemPool* mempool) {
    return mempool->object_size;
}

void* rawstd_mempool_data(RawstdMemPool* mempool) {
    return mempool->data;
}

void* rawstd_mempool_alloc(RawstdMemPool* mempool) {
    if (mempool->current == mempool->tail) {
        errno = ENOBUFS;
        return NULL;
    }
    return *(mempool->current++);
}

void rawstd_mempool_free(RawstdMemPool* mempool, void* ptr) {
    *(--mempool->current) = ptr;
}
