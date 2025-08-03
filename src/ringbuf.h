#ifndef RAWSTOR_RINGBUF_H
#define RAWSTOR_RINGBUF_H

#include <stddef.h>


typedef struct RawstorRingBuf RawstorRingBuf;

RawstorRingBuf* rawstor_ringbuf_create(size_t capacity, size_t object_size);

void rawstor_ringbuf_delete(RawstorRingBuf *buf);

void* rawstor_ringbuf_head(RawstorRingBuf *buf);

void* rawstor_ringbuf_tail(RawstorRingBuf *buf);

int rawstor_ringbuf_push(RawstorRingBuf *buf);

int rawstor_ringbuf_pop(RawstorRingBuf *buf);

int rawstor_ringbuf_empty(RawstorRingBuf *buf);

size_t rawstor_ringbuf_size(RawstorRingBuf *buf);

void* rawstor_ringbuf_iter(RawstorRingBuf *buf);

void* rawstor_ringbuf_next(RawstorRingBuf *buf, void *iter);


#endif // RAWSTOR_RINGBUF_H
