#include "tenant.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const columns[] = {"tenant_id"};
static const enum RawstorCliColumnType types[] = {RAWSTOR_CLI_COLUMN_STRING};

int rawstor_cli_tenant_create(
    const char* location, const char* tenant, const RawstorCliOutput* output
) {
    /* Rejects a bad --column before the tenant is registered: afterwards the
     * only thing left to report is its id, and a retry would register
     * another. */
    RawstorCliTable* table =
        rawstor_cli_record_create("tenant", columns, types, 1);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }
    int checked = rawstor_cli_output_check(output, &table, 1);
    if (checked != EXIT_SUCCESS) {
        rawstor_cli_table_delete(table);
        return checked;
    }

    RawstdUUIDString generated;
    if (tenant == NULL) {
        struct RawstdUUID id;
        int ires = rawstd_uuid7_init(&id);
        if (ires < 0) {
            fprintf(stderr, "Failed to generate a tenant id\n");
            rawstor_cli_table_delete(table);
            return rawstd_exitcode_for_errno(-ires);
        }
        rawstd_uuid_to_string(&id, &generated);
        tenant = generated;
    }

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_location_create_tenant(
        op.queue, location, tenant, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_create_tenant() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    RawstorCliCell cells[] = {rawstor_cli_cell_string(tenant)};
    int ret = EXIT_FAILURE;
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
    } else {
        ret = rawstor_cli_output_print(output, &table, 1);
    }
    rawstor_cli_table_delete(table);
    return ret;
}

int rawstor_cli_tenant_remove(const char* location, const char* tenant) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_location_remove_tenant(
        op.queue, location, tenant, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_remove_tenant() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Tenant removed\n");
    return EXIT_SUCCESS;
}

int rawstor_cli_tenant_list(
    const char* location, const RawstorCliOutput* output
) {
    RawstorCliTable* table =
        rawstor_cli_table_create("tenants", columns, types, 1);
    if (table == NULL) {
        fprintf(stderr, "Out of memory\n");
        return EXIT_FAILURE;
    }

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        rawstor_cli_table_delete(table);
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* tenants = NULL;
    RawstorPaginationToken token = {};
    do {
        op.done = 0;
        int sres = rawstor_location_tenants(
            op.queue, location, 0, &tenants, &token, rawstor_cli_op_cb, &op
        );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result < 0) {
            fprintf(
                stderr, "rawstor_location_tenants() failed: %s\n",
                strerror((int)-result)
            );
            rawstor_cli_op_destroy(&op);
            rawstor_cli_table_delete(table);
            return rawstd_exitcode_for_errno((int)-result);
        }
        for (const char** it = rawstor_string_list_iter(tenants); it != NULL;
             it = rawstor_string_list_next(it)) {
            RawstorCliCell cells[] = {rawstor_cli_cell_string(*it)};
            if (rawstor_cli_table_add_row(table, cells) < 0) {
                fprintf(stderr, "Out of memory\n");
                rawstor_string_list_delete(tenants);
                rawstor_cli_op_destroy(&op);
                rawstor_cli_table_delete(table);
                return EXIT_FAILURE;
            }
        }
        rawstor_string_list_delete(tenants);
    } while (!rawstor_pagination_token_empty(&token));

    rawstor_cli_op_destroy(&op);
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}
