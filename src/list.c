#include <rawstor/list.h>

#include <rawstd/list.h>

#include <stdlib.h>

void rawstor_string_list_delete(RawstorStringList* list) {
    if (list != NULL) {
        for (const char** it = rawstor_string_list_iter(list); it != NULL;
             it = rawstor_string_list_next(it)) {
            free((char*)*it);
        }
    }
    rawstd_list_delete((RawstdList*)list);
}

const char** rawstor_string_list_iter(RawstorStringList* list) {
    return (const char**)rawstd_list_iter((RawstdList*)list);
}

const char** rawstor_string_list_next(const char** iter) {
    return (const char**)rawstd_list_next(iter);
}

int rawstor_string_list_empty(RawstorStringList* list) {
    return rawstd_list_empty((RawstdList*)list);
}

size_t rawstor_string_list_size(RawstorStringList* list) {
    return rawstd_list_size((RawstdList*)list);
}
