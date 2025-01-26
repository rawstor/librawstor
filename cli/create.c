#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>


int rawstor_cli_create(size_t size) {
    if (rawstor_initialize()) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    struct RawstorDeviceSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating device with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);
    int device_id;
    if (rawstor_create(spec, &device_id)) {
        perror("rawstor_create() failed");
        return EXIT_FAILURE;
    }
    fprintf(stderr, "Device created\n");
    fprintf(stdout, "%d\n", device_id);

    rawstor_terminate();

    return EXIT_SUCCESS;
}
