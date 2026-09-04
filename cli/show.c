#include "show.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_show(const char* target) {
    struct RawstorObjectSpec spec;

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres =
        rawstor_target_spec(op.queue, target, &spec, rawstor_cli_op_cb, &op);
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_spec() failed: %s\n", strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    char buf[256];
    rawstd_bytes_to_size(spec.size, buf, sizeof(buf));

    printf("target: %s\n", target);
    printf("size: %s\n", buf);
    printf("replicas: %u\n", spec.mirror_count);

    return EXIT_SUCCESS;
}
