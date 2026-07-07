#include "list.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_list(const char* location) {
    RawstorStringList* targets;
    void* marker = NULL;
    do {
        int res = rawstor_object_list(location, 0, &targets, &marker);
        if (res < 0) {
            fprintf(
                stderr, "rawstor_object_list() failed: %s\n", strerror(-res)
            );
            return EXIT_FAILURE;
        }
        for (const char** it = rawstor_string_list_iter(targets); it != NULL;
             it = rawstor_string_list_next(it)) {
            printf("%s\n", *it);
        }
        rawstor_string_list_delete(targets);
    } while (marker != NULL);

    return EXIT_SUCCESS;
}
