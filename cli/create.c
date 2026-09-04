#include "create.h"

#include "rawio_sync.h"

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
    fprintf(output, "  replicas: %u\n", spec->mirror_count);
}

int rawstor_cli_create(
    const char* target, uint64_t size, unsigned int mirror_count
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .mirror_count = mirror_count,
    };

    fprintf(stderr, "Creating object with specification:\n");
    log_spec(stderr, &spec);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres =
        rawstor_target_create(op.queue, target, &spec, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_create() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    return EXIT_SUCCESS;
}

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size,
    unsigned int mirror_count
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .mirror_count = mirror_count,
    };

    fprintf(stderr, "Creating object with specification:\n");
    log_spec(stderr, &spec);

    char target[65536];

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_location_create(
        op.queue, location, uuid, &spec, target, sizeof(target),
        rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_create() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    if (result >= (ssize_t)sizeof(target)) {
        fprintf(stderr, "rawstor_location_create(): output truncated\n");
        return EX_SOFTWARE;
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    return EXIT_SUCCESS;
}
