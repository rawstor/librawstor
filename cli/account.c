#include "account.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/uuid.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char* const columns[] = {"account_id"};
static const enum RawstorCliColumnType types[] = {RAWSTOR_CLI_COLUMN_STRING};

int rawstor_cli_account_create(
    const char* location, const char* account, const RawstorCliOutput* output
) {
    /* Rejects a bad --column before the account is registered: afterwards the
     * only thing left to report is its id, and a retry would register
     * another. */
    RawstorCliTable* table =
        rawstor_cli_record_create("account", columns, types, 1);
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
    if (account == NULL) {
        struct RawstdUUID id;
        int ires = rawstd_uuid7_init(&id);
        if (ires < 0) {
            fprintf(stderr, "Failed to generate an account id\n");
            rawstor_cli_table_delete(table);
            return rawstd_exitcode_for_errno(-ires);
        }
        rawstd_uuid_to_string(&id, &generated);
        account = generated;
    }

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_location_create_account(
        op.queue, location, account, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_create_account() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    RawstorCliCell cells[] = {rawstor_cli_cell_string(account)};
    int ret = EXIT_FAILURE;
    if (rawstor_cli_table_add_row(table, cells) < 0) {
        fprintf(stderr, "Out of memory\n");
    } else {
        ret = rawstor_cli_output_print(output, &table, 1);
    }
    rawstor_cli_table_delete(table);
    return ret;
}

int rawstor_cli_account_remove(const char* location, const char* account) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_location_remove_account(
        op.queue, location, account, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_location_remove_account() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Account removed\n");
    return EXIT_SUCCESS;
}

int rawstor_cli_transfer(const char* target, const char* account) {
    fprintf(stderr, "Transferring object to account %s\n", account);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_target_transfer(
        op.queue, target, account, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_transfer() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Object transferred\n");
    return EXIT_SUCCESS;
}

int rawstor_cli_account_list(
    const char* location, const RawstorCliOutput* output
) {
    RawstorCliTable* table =
        rawstor_cli_table_create("accounts", columns, types, 1);
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

    RawstorStringList* accounts = NULL;
    RawstorPaginationToken token = {};
    do {
        op.done = 0;
        int sres = rawstor_location_accounts(
            op.queue, location, 0, &accounts, &token, rawstor_cli_op_cb, &op
        );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result < 0) {
            fprintf(
                stderr, "rawstor_location_accounts() failed: %s\n",
                strerror((int)-result)
            );
            rawstor_cli_op_destroy(&op);
            rawstor_cli_table_delete(table);
            return rawstd_exitcode_for_errno((int)-result);
        }
        for (const char** it = rawstor_string_list_iter(accounts); it != NULL;
             it = rawstor_string_list_next(it)) {
            RawstorCliCell cells[] = {rawstor_cli_cell_string(*it)};
            if (rawstor_cli_table_add_row(table, cells) < 0) {
                fprintf(stderr, "Out of memory\n");
                rawstor_string_list_delete(accounts);
                rawstor_cli_op_destroy(&op);
                rawstor_cli_table_delete(table);
                return EXIT_FAILURE;
            }
        }
        rawstor_string_list_delete(accounts);
    } while (!rawstor_pagination_token_empty(&token));

    rawstor_cli_op_destroy(&op);
    int ret = rawstor_cli_output_print(output, &table, 1);
    rawstor_cli_table_delete(table);
    return ret;
}
