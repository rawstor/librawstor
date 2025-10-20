#include "remove.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_remove(const char *uris) {
    fprintf(stderr, "Removing object: %s\n", uris);

    int res = rawstor_object_remove(uris);
    if (res) {
        fprintf(
            stderr,
            "rawstor_object_remove() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Object removed\n");

    return EXIT_SUCCESS;
}
