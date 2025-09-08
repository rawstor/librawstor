#include "remove.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_remove(
    const struct RawstorOpts *opts,
    const struct RawstorSocketAddress *default_ost,
    const struct RawstorUUID *object_id)
{
    if (rawstor_initialize(opts, default_ost)) {
        perror("rawstor_initialize() failed");
        goto err_initialize;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);
    fprintf(stderr, "Removing object with id: %s\n", uuid_string);
    if (rawstor_object_remove(object_id)) {
        perror("rawstor_object_remove() failed");
        goto err_remove;
    }

    fprintf(stderr, "Object removed\n");

    rawstor_terminate();

    return EXIT_SUCCESS;

err_remove:
    rawstor_terminate();
err_initialize:
    return EXIT_FAILURE;
}
