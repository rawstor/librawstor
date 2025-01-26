#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>


int rawstor_cli_create(size_t size) {
    if (rawstor_initialize()) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    struct RawstorVolumeSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating volume with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);
    int volume_id;
    if (rawstor_create(spec, &volume_id)) {
        perror("rawstor_create() failed");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Volume created\n");
    fprintf(stdout, "%d\n", volume_id);

    rawstor_terminate();

    return EXIT_SUCCESS;
}
