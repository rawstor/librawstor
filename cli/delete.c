#include "delete.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_delete(
    const struct RawstorOpts *opts,
    const struct RawstorOptsOST *opts_ost,
    const struct RawstorUUID *object_id)
{
    if (rawstor_initialize(opts, opts_ost)) {
        perror("rawstor_initialize() failed");
        goto err_initialize;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);
    fprintf(stderr, "Deleting object with id: %s\n", uuid_string);
    if (rawstor_object_delete(NULL, object_id)) {
        perror("rawstor_object_delete() failed");
        goto err_delete;
    }

    fprintf(stderr, "Object deleted\n");

    rawstor_terminate();

    return EXIT_SUCCESS;

err_delete:
    rawstor_terminate();
err_initialize:
    return EXIT_FAILURE;
}
