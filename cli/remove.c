#include "remove.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_remove(const char* target) {
    fprintf(stderr, "Removing object: %s\n", target);

    int res = rawstor_object_remove(target);
    if (res) {
        fprintf(stderr, "rawstor_object_remove() failed: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    fprintf(stderr, "Object removed\n");

    return EXIT_SUCCESS;
}
