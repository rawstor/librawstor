#include "remove.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_remove(const struct RawstorUUID *object_id) {
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);
    fprintf(stderr, "Removing object with id: %s\n", uuid_string);

    int res = rawstor_object_remove(object_id);
    if (res) {
        fprintf(
            stderr,
            "rawstor_object_remove() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Object removed\n");

    return EXIT_SUCCESS;
}
