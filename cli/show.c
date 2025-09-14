#include "show.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_show(
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

    struct RawstorObjectSpec spec;
    if (rawstor_object_spec(object_id, &spec)) {
        perror("rawstor_object_spec() failed");
        goto err_spec;
    }

    printf("id: %s\n", uuid_string);
    printf("size: %zu Gb\n", spec.size >> 30);

    rawstor_terminate();

    return EXIT_SUCCESS;

err_spec:
    rawstor_terminate();
err_initialize:
    return EXIT_FAILURE;
}
