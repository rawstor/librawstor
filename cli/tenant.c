#include "tenant.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_tenant_create(const char* location, const char* tenant) {
    RawstdUUIDString generated;
    if (tenant == NULL) {
        struct RawstdUUID id;
        int ires = rawstd_uuid7_init(&id);
        if (ires < 0) {
            fprintf(stderr, "Failed to generate a tenant id\n");
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

    printf("%s\n", tenant);
    return EXIT_SUCCESS;
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

int rawstor_cli_tenant_list(const char* location) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* tenants = NULL;
    int sres = rawstor_location_tenants(
        op.queue, location, &tenants, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_tenants() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    for (const char** it = rawstor_string_list_iter(tenants); it != NULL;
         it = rawstor_string_list_next(it)) {
        printf("%s\n", *it);
    }
    rawstor_string_list_delete(tenants);
    return EXIT_SUCCESS;
}
