#include "create.h"

#include "units.h"
#include "uri.h"

#include <rawstor.h>

#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_create(const char* location, size_t size) {
    struct RawstdUUID uuid;
    int res = rawstd_uuid7_init(&uuid);
    if (res) {
        fprintf(stderr, "rawstd_uuid7_init() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    char target[65536];
    res = rawstor_cli_location_add_target(
        location, &uuid, target, sizeof(target)
    );
    if (res < 0) {
        fprintf(
            stderr, "rawstor_cli_location_add_target() failed: %s\n",
            strerror(-res)
        );
        return EXIT_FAILURE;
    }

    struct RawstorObjectSpec spec = {
        .size = size,
    };
    char buf[256];
    rawstor_cli_bytes_to_size(size, buf, sizeof(buf));

    fprintf(stderr, "Creating object with specification:\n");
    fprintf(stderr, "  size: %s\n", buf);

    res = rawstor_object_create(target, &spec);
    if (res < 0) {
        fprintf(stderr, "rawstor_object_create() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    return EXIT_SUCCESS;
}
