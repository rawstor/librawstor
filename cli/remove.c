#include "remove.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_remove(const char* target) {
    fprintf(stderr, "Removing object: %s\n", target);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_target_remove(op.queue, target, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_remove() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Object removed\n");

    return EXIT_SUCCESS;
}
