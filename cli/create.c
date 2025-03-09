#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>


int rawstor_cli_create(const RawstorConfig *config, size_t size) {
    if (rawstor_initialize(config)) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    RawstorObjectSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);
    int object_id;
    if (rawstor_object_create(&spec, &object_id)) {
        perror("rawstor_object_create() failed");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%d\n", object_id);

    rawstor_terminate();

    return EXIT_SUCCESS;
}
