#include "create.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void log_spec(FILE* output, const struct RawstorObjectSpec* spec) {
    char buf[256];
    rawstd_bytes_to_size(spec->size, buf, sizeof(buf));

    fprintf(output, "  size: %s\n", buf);
    fprintf(output, "  mirrors: %u\n", spec->width);

    /* chunk_size is meaningful for both a plain object (create-by-location
     * splits it itself) and an mds:// one; failure_domain/stripe_width are
     * mds:// object policy only. Silently unused otherwise. */
    if (spec->chunk_size != 0) {
        rawstd_bytes_to_size(spec->chunk_size, buf, sizeof(buf));
        fprintf(output, "  chunk size: %s\n", buf);
    }
    if (spec->failure_domain != 0) {
        fprintf(output, "  failure domain: %u\n", spec->failure_domain);
    }
    if (spec->stripe_width != 0) {
        fprintf(
            output, "  stripe width: %llu\n",
            (unsigned long long)spec->stripe_width
        );
    }
}

int rawstor_cli_create(
    const char* target, uint64_t size, uint64_t chunk_size,
    unsigned int mirrors, uint8_t failure_domain, uint64_t stripe_width
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .width = mirrors,
        .chunk_size = chunk_size,
        .stripe_width = stripe_width,
        .failure_domain = failure_domain,
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

// One rawstor_location_create() attempt against a fresh queue, driven to
// completion synchronously -- returns its own result unchanged (the
// target string's own length on success, negative errno on failure;
// rawstor_cli_op_init()'s own failure already comes back in that same
// shape, a negative errno).
static ssize_t try_location_create(
    const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size
) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        return res;
    }

    int sres = rawstor_location_create(
        op.queue, location, uuid, spec, target, size, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    return result;
}

int rawstor_cli_create_at(
    const char* location, const char* uuid, uint64_t size, uint64_t chunk_size,
    unsigned int mirrors, uint8_t failure_domain, uint64_t stripe_width
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .width = mirrors,
        .chunk_size = chunk_size,
        .stripe_width = stripe_width,
        .failure_domain = failure_domain,
    };

    fprintf(stderr, "Creating object with specification:\n");
    log_spec(stderr, &spec);

    // NULL/0 asks for the target string's own length alone -- the same
    // snprintf(NULL, 0, ...) idiom rawstor_location_create() itself just
    // forwards to (location.cpp), needing no I/O and creating nothing.
    // The second call, into a buffer sized exactly for that length, does
    // the real work.
    ssize_t result = try_location_create(location, uuid, &spec, NULL, 0);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_create() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    char* target = malloc((size_t)result + 1);
    if (target == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    result =
        try_location_create(location, uuid, &spec, target, (size_t)result + 1);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_create() failed: %s\n",
            strerror((int)-result)
        );
        free(target);
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Object created\n");
    fprintf(stdout, "%s\n", target);

    free(target);

    return EXIT_SUCCESS;
}
