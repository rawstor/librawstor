#ifndef RAWSTD_LIST_H
#define RAWSTD_LIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstdList RawstdList;

RawstdList* rawstd_list_create(size_t object_size);

void rawstd_list_delete(RawstdList* list);

void* rawstd_list_iter(RawstdList* list);

void* rawstd_list_next(void* iter);

void* rawstd_list_append(RawstdList* list);

void* rawstd_list_remove(RawstdList* list, void* iter);

int rawstd_list_empty(RawstdList* list);

size_t rawstd_list_size(RawstdList* list);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_LIST_H
