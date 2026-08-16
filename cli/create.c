#include "create.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

static void log_spec(FILE* output, const struct RawstorObjectSpec* spec) {
    char buf[256];
    rawstd_bytes_to_size(spec->size, buf, sizeof(buf));

    fprintf(output, "  size: %s\n", buf);
}

int rawstor_cli_create(
    const char* target, uint64_t size, uint64_t chunk_size, unsigned width
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .chunk_size = chunk_size,
        .width = (uint8_t)width,
    };

    fprintf(stderr, "Creating object with specification:\n");
    log_spec(stderr, &spec);

    int res = rawstor_object_create(target, &spec);
    if (res < 0) {
        fprintf(stderr, "rawstor_object_create() failed: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    return EXIT_SUCCESS;
}

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size
) {
    return rawstor_cli_create_at_vol(location, uuid, size, 0, 0);
}

int rawstor_cli_create_at_vol(
    const char* location, const char* uuid, uint64_t size, uint64_t chunk_size,
    unsigned width
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .chunk_size = chunk_size,
        .width = (uint8_t)width,
    };

    fprintf(stderr, "Creating object with specification:\n");
    log_spec(stderr, &spec);

    char target[65536];
    int res =
        rawstor_object_create_at(location, uuid, &spec, target, sizeof(target));
    if (res < 0) {
        fprintf(
            stderr, "rawstor_object_create_at() failed: %s\n", strerror(-res)
        );
        return rawstd_exitcode_for_errno(-res);
    }

    if (res >= (int)sizeof(target)) {
        fprintf(stderr, "rawstor_object_create_at(): output truncated\n");
        return EX_SOFTWARE;
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    return EXIT_SUCCESS;
}
