#include "list.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_list(const char* location) {
    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    do {
        int res = rawstor_object_list(location, 0, &targets, &token);
        if (res < 0) {
            fprintf(
                stderr, "rawstor_object_list() failed: %s\n", strerror(-res)
            );
            return rawstd_exitcode_for_errno(-res);
        }
        for (const char** it = rawstor_string_list_iter(targets); it != NULL;
             it = rawstor_string_list_next(it)) {
            printf("%s\n", *it);
        }
        rawstor_string_list_delete(targets);
    } while (!rawstor_pagination_token_empty(&token));

    return EXIT_SUCCESS;
}
