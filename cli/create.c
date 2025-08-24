#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>


int rawstor_cli_create(
    const struct RawstorOptsIO *opts_io,
    const struct RawstorOptsOST *opts_ost,
    size_t size)
{
    if (rawstor_initialize(opts_io, opts_ost)) {
        perror("rawstor_initialize() failed");
        return EXIT_FAILURE;
    }

    RawstorObjectSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);
    RawstorUUID object_id;
    if (rawstor_object_create(NULL, &spec, &object_id)) {
        perror("rawstor_object_create() failed");
        return EXIT_FAILURE;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&object_id, &uuid_string);
    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", uuid_string);

    rawstor_terminate();

    return EXIT_SUCCESS;
}
