#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_create(const char *uris, size_t size){
    struct RawstorObjectSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);

    char object_uris[65536];
    int res = rawstor_object_create(
        uris, &spec, object_uris, sizeof(object_uris));
    if (res < 0) {
        fprintf(
            stderr,
            "rawstor_object_create() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", object_uris);

    return EXIT_SUCCESS;
}
