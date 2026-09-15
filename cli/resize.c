#include "resize.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_resize(const char* target, uint64_t new_size) {
    char buf[256];
    rawstd_bytes_to_size(new_size, buf, sizeof(buf));
    fprintf(stderr, "Resizing volume %s to %s\n", target, buf);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int sres = rawstor_volume_resize(
        op.queue, target, new_size, rawstor_cli_op_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    if (result < 0) {
        fprintf(
            stderr, "rawstor_volume_resize() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Volume resized\n");

    return EXIT_SUCCESS;
}
