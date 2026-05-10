#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_create(const char* location, size_t size) {
    struct RawstorObjectSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);

    char target[65536];
    int res = rawstor_object_create(location, &spec, target, sizeof(target));
    if (res < 0) {
        fprintf(stderr, "rawstor_object_create() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    return EXIT_SUCCESS;
}
