#ifndef _RAWSTOR_STACK_BUFFER_H_
#define _RAWSTOR_STACK_BUFFER_H_

#include <stddef.h>


typedef struct RawstorSB RawstorSB;


RawstorSB* rawstor_sb_create(unsigned int depth, size_t item_size);

void rawstor_sb_delete(RawstorSB *buffer);

void* rawstor_sb_acquire(RawstorSB *buffer);

void rawstor_sb_release(RawstorSB *buffer, void *item);


#endif // _RAWSTOR_STACK_BUFFER_H_
