#include "create.h"

#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_create(const char *uri, size_t size){
    struct RawstorObjectSpec spec = {
        .size = size << 30,
    };

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %zu Gb\n", size);
    struct RawstorUUID object_id;

    int res = rawstor_object_create(uri, &spec, &object_id);
    if (res) {
        fprintf(
            stderr,
            "rawstor_object_create() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&object_id, &uuid_string);
    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s/%s\n", uri, uuid_string);

    return EXIT_SUCCESS;
}
