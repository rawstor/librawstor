#include "ringbuf.h"

#include <errno.h>
#include <stdlib.h>


struct RawstorRingBuf {
    void *data;
    size_t capacity;
    size_t object_size;
    size_t head;
    size_t tail;
};


RawstorRingBuf* rawstor_ringbuf_create(size_t capacity, size_t object_size) {
    if (capacity == 0) {
        errno = EINVAL;
        return NULL;
    }

    RawstorRingBuf *buf = malloc(sizeof(RawstorRingBuf));
    if (buf == NULL) {
        goto err_buf;
    }

    buf->capacity = capacity + 1;
    buf->object_size = object_size;
    buf->head = 0;
    buf->tail = 0;
    buf->data = calloc(buf->capacity, object_size);
    if (buf->data == NULL) {
        goto err_data;
    }

    return buf;

err_data:
    free(buf);
err_buf:
    return NULL;
}


void rawstor_ringbuf_delete(RawstorRingBuf *buf) {
    free(buf->data);
    free(buf);
}


void* rawstor_ringbuf_head(RawstorRingBuf *buf) {
    return buf->data + buf->head * buf->object_size;
}


void* rawstor_ringbuf_tail(RawstorRingBuf *buf) {
    return buf->data + buf->tail * buf->object_size;
}


int rawstor_ringbuf_push(RawstorRingBuf *buf) {
    size_t next = (buf->head + 1) % buf->capacity;
    if (next == buf->tail) {
        errno = ENOBUFS;
        return -errno;
    }

    buf->head = next;

    return 0;
}


int rawstor_ringbuf_pop(RawstorRingBuf *buf) {
    if (buf->tail == buf->head) {
        errno = ENOBUFS;
        return -errno;
    }

    buf->tail = (buf->tail + 1) % buf->capacity;

    return 0;
}


int rawstor_ringbuf_empty(RawstorRingBuf *buf) {
    return buf->tail == buf->head;
}


size_t rawstor_ringbuf_size(RawstorRingBuf *buf) {
    return (buf->capacity + buf->head - buf->tail) % buf->capacity;
}


void* rawstor_ringbuf_iter(RawstorRingBuf *buf) {
    if (rawstor_ringbuf_empty(buf)) {
        return NULL;
    }
    return rawstor_ringbuf_tail(buf);
}


void* rawstor_ringbuf_next(RawstorRingBuf *buf, void *iter) {
    iter += buf->object_size;

    if (iter >= buf->data + buf->capacity * buf->object_size) {
        iter = buf->data;
    }

    if (iter == rawstor_ringbuf_head(buf)) {
        return NULL;
    }

    return iter;
}
