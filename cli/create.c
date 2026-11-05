#include "create.h"

#include "output.h"
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

static const char* const created_columns[] = {
    "object_id",  "target",         "size",         "mirrors",
    "chunk_size", "failure_domain", "stripe_width",
};
static const enum RawstorCliColumnType created_types[] = {
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_SIZE,   RAWSTOR_CLI_COLUMN_NUMBER,
    RAWSTOR_CLI_COLUMN_SIZE,   RAWSTOR_CLI_COLUMN_NUMBER,
    RAWSTOR_CLI_COLUMN_NUMBER,
};
enum { CREATED_COLUMNS = 7 };

/* Rejects a bad --column before an object is created: once it exists, the
 * only thing left to report is its target, and a retry would create another
 * object. */
static int check_created_output(const RawstorCliOutput* output) {
    RawstorCliTable* table = rawstor_cli_record_create(
        "object", created_columns, created_types, CREATED_COLUMNS
    );
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int ret = rawstor_cli_output_check(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}

/* Prints the created object's target together with its specification;
 * `--format value --column target` yields just the target. A policy that was
 * left at its default is an empty cell. */
static int print_created(
    const RawstorCliOutput* output, const char* target,
    const struct RawstorObjectSpec* spec
) {
    char mirrors_buf[32];
    char domain_buf[32];
    char stripe_buf[32];
    snprintf(mirrors_buf, sizeof(mirrors_buf), "%u", spec->width);
    snprintf(domain_buf, sizeof(domain_buf), "%u", spec->failure_domain);
    snprintf(
        stripe_buf, sizeof(stripe_buf), "%llu",
        (unsigned long long)spec->stripe_width
    );
    char uuid[64];
    char version[64];
    rawstor_cli_target_ids(
        target, uuid, sizeof(uuid), version, sizeof(version)
    );
    RawstorCliCell cells[] = {
        rawstor_cli_cell_optional(uuid),
        rawstor_cli_cell_string(target),
        rawstor_cli_cell_size(spec->size),
        rawstor_cli_cell_number(mirrors_buf, spec->width),
        spec->chunk_size != 0 ? rawstor_cli_cell_size(spec->chunk_size)
                              : rawstor_cli_cell_number(NULL, 0),
        rawstor_cli_cell_number(
            spec->failure_domain != 0 ? domain_buf : NULL, spec->failure_domain
        ),
        rawstor_cli_cell_number(
            spec->stripe_width != 0 ? stripe_buf : NULL, spec->stripe_width
        ),
    };

    RawstorCliTable* table = rawstor_cli_record_create(
        "object", created_columns, created_types, CREATED_COLUMNS
    );
    if (table == NULL || rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
        if (table != NULL) {
            rawstor_cli_table_delete(table);
        }
        return EXIT_FAILURE;
    }
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}

int rawstor_cli_create(
    const char* target, uint64_t size, uint64_t chunk_size,
    unsigned int mirrors, unsigned int failure_domain, uint64_t stripe_width,
    const RawstorCliOutput* output
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .width = mirrors,
        .chunk_size = chunk_size,
        .stripe_width = stripe_width,
        .failure_domain = failure_domain,
    };

    int checked = check_created_output(output);
    if (checked != 0) {
        return checked;
    }

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
    return print_created(output, target, &spec);
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
    unsigned int mirrors, unsigned int failure_domain, uint64_t stripe_width,
    const RawstorCliOutput* output
) {
    struct RawstorObjectSpec spec = {
        .size = size,
        .width = mirrors,
        .chunk_size = chunk_size,
        .stripe_width = stripe_width,
        .failure_domain = failure_domain,
    };

    int checked = check_created_output(output);
    if (checked != 0) {
        return checked;
    }

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
    int ret = print_created(output, target, &spec);

    free(target);

    return ret;
}
