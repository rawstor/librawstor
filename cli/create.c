#include "create.h"

#include "image.h"
#include "output.h"
#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const created_columns[] = {
    "object_id", "account",    "target",         "size",
    "mirrors",   "chunk_size", "failure_domain", "stripe_width",
};
static const enum RawstorCliColumnType created_types[] = {
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_STRING,
    RAWSTOR_CLI_COLUMN_STRING, RAWSTOR_CLI_COLUMN_SIZE,
    RAWSTOR_CLI_COLUMN_NUMBER, RAWSTOR_CLI_COLUMN_SIZE,
    RAWSTOR_CLI_COLUMN_NUMBER, RAWSTOR_CLI_COLUMN_NUMBER,
};
enum { CREATED_COLUMNS = 8 };

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
    /* The owner is read back: it is what was stored, not what was asked. */
    char account[64] = "";
    RawstorCliOp op;
    if (rawstor_cli_op_init(&op) == 0) {
        int ores = rawstor_cli_op_owner(&op, target, account, sizeof(account));
        rawstor_cli_op_destroy(&op);
        if (ores < 0) {
            fprintf(
                stderr, "rawstor_target_meta() failed: %s\n", strerror(-ores)
            );
            account[0] = '\0';
        }
    }
    RawstorCliCell cells[] = {
        rawstor_cli_cell_optional(uuid),
        rawstor_cli_cell_optional(account),
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

    fprintf(stderr, "Creating object: %s\n", target);

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

    fprintf(stderr, "Creating object: %s\n", location);

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

int rawstor_cli_import(
    const char* target, const char* from_file, const char* from_target,
    uint64_t size, uint64_t chunk_size, unsigned int mirrors,
    unsigned int failure_domain, uint64_t stripe_width,
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

    fprintf(
        stderr, "Creating object %s from %s\n", target,
        from_file != NULL ? from_file : from_target
    );

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    op.on_progress = rawstor_cli_progress;
    const char* call;
    int sres;
    if (from_file != NULL) {
        call = "rawstor_target_create_from_file()";
        sres = rawstor_target_create_from_file(
            op.queue, target, from_file, &spec, rawstor_cli_op_progress_cb, &op
        );
    } else {
        call = "rawstor_target_create_from_target()";
        sres = rawstor_target_create_from_target(
            op.queue, target, from_target, &spec, rawstor_cli_op_progress_cb,
            &op
        );
    }
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    rawstor_cli_progress_end();
    if (result < 0) {
        fprintf(stderr, "%s failed: %s\n", call, strerror((int)-result));
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Object created\n");

    /* A size left to the source is only known now: read it back. */
    struct RawstorObjectSpec stored = spec;
    if (stored.size == 0) {
        struct RawstorObjectSpec read_spec;
        memset(&read_spec, 0, sizeof(read_spec));
        if (rawstor_cli_op_init(&op) == 0) {
            int spres = rawstor_target_spec(
                op.queue, target, &read_spec, rawstor_cli_op_cb, &op
            );
            ssize_t spec_result = rawstor_cli_op_wait(&op, spres);
            rawstor_cli_op_destroy(&op);
            if (spec_result == 0) {
                stored.size = read_spec.size;
            }
        }
    }
    return print_created(output, target, &stored);
}
