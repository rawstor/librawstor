#include "list.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_list(const char* location) {
    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    RawstorStringList* targets;
    RawstorPaginationToken token = {};
    do {
        op.done = 0;
        int sres = rawstor_location_list(
            op.queue, location, 0, &targets, &token, rawstor_cli_op_cb, &op
        );
        ssize_t result = rawstor_cli_op_wait(&op, sres);
        if (result < 0) {
            fprintf(
                stderr, "rawstor_location_list() failed: %s\n",
                strerror((int)-result)
            );
            rawstor_cli_op_destroy(&op);
            return rawstd_exitcode_for_errno((int)-result);
        }
        for (const char** it = rawstor_string_list_iter(targets); it != NULL;
             it = rawstor_string_list_next(it)) {
            printf("%s\n", *it);
        }
        rawstor_string_list_delete(targets);
    } while (!rawstor_pagination_token_empty(&token));

    rawstor_cli_op_destroy(&op);
    return EXIT_SUCCESS;
}
