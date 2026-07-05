#ifndef RAWSTOR_LIST_H
#define RAWSTOR_LIST_H

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorStringList RawstorStringList;

void rawstor_string_list_delete(RawstorStringList* list);

const char** rawstor_string_list_iter(RawstorStringList* list);

const char** rawstor_string_list_next(const char** iter);

int rawstor_string_list_empty(RawstorStringList* list);

size_t rawstor_string_list_size(RawstorStringList* list);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_LIST_H
