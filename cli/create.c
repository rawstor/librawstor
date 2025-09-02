#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>


int rawstor_cli_create(
    const struct RawstorOpts *opts,
    const struct RawstorOptsOST *opts_ost,
    size_t size)
{
    if (rawstor_initialize(opts, opts_ost)) {
        perror("rawstor_initialize() failed");
        goto err_initialize;
    }

    struct RawstorObjectSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);
    struct RawstorUUID object_id;
    if (rawstor_object_create(NULL, &spec, &object_id)) {
        perror("rawstor_object_create() failed");
        goto err_create;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&object_id, &uuid_string);
    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", uuid_string);

    rawstor_terminate();

    return EXIT_SUCCESS;

err_create:
    rawstor_terminate();
err_initialize:
    return EXIT_FAILURE;
}
