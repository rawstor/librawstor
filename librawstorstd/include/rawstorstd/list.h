#ifndef RAWSTORSTD_LIST_H
#define RAWSTORSTD_LIST_H

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorList RawstorList;


RawstorList* rawstor_list_create(size_t object_size);

void rawstor_list_delete(RawstorList *list);

void* rawstor_list_iter(RawstorList *list);

void* rawstor_list_next(void *iter);

void* rawstor_list_append(RawstorList *list);

void* rawstor_list_remove(RawstorList *list, void *iter);

int rawstor_list_empty(RawstorList *list);

size_t rawstor_list_size(RawstorList *list);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORSTD_LIST_H
