#include "stack_buffer.h"

#include <errno.h>
#include <stdlib.h>


#define RAWSTOR_SB_HDR_SIZE (sizeof(RawstorSB))
#define RAWSTOR_SB_TO_DATA(sb) ((void*)sb + RAWSTOR_SB_HDR_SIZE)
#define RAWSTOR_DATA_TO_SB(ptr) ((void*)ptr - RAWSTOR_SB_HDR_SIZE)


typedef struct RawstorSB {
    RawstorSB *next;
} RawstorSB;


RawstorSB* rawstor_sb_create(unsigned int depth, size_t item_size) {
    RawstorSB *head = malloc(RAWSTOR_SB_HDR_SIZE);
    if (head == NULL) {
        return NULL;
    }
    head->next = NULL;

    for (unsigned int i = 0; i < depth; ++i) {
        RawstorSB *next = malloc(RAWSTOR_SB_HDR_SIZE + item_size);
        if (next == NULL) {
            int errsv = errno;
            rawstor_sb_delete(head);
            errno = errsv;
            return NULL;
        }

        next->next = head->next;
        head->next = next;
    }

    return head;
}


void rawstor_sb_delete(RawstorSB *buffer) {
    RawstorSB *at = buffer;
    while (at != NULL) {
        RawstorSB *next = at->next;
        free(at);
        at = next;
    }
}


void* rawstor_sb_acquire(RawstorSB *buffer) {
    RawstorSB *sb = buffer->next;
    if (sb == NULL) {
        errno = ENOBUFS;
        return NULL;
    }

    buffer->next = sb->next;
    sb->next = NULL;
    return RAWSTOR_SB_TO_DATA(sb);
}


void rawstor_sb_release(RawstorSB *buffer, void *ptr) {
    RawstorSB *sb = RAWSTOR_DATA_TO_SB(ptr);
    sb->next = buffer->next;
    buffer->next = sb;
}
