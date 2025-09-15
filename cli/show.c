#include "show.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_show(const struct RawstorUUID *object_id) {
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);

    struct RawstorObjectSpec spec;
    if (rawstor_object_spec(object_id, &spec)) {
        perror("rawstor_object_spec() failed");
        return EXIT_FAILURE;
    }

    printf("id: %s\n", uuid_string);
    printf("size: %zu Gb\n", spec.size >> 30);

    return EXIT_SUCCESS;
}
