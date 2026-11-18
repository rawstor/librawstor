#include "image.h"

#include "rawio_sync.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static int progress_last = -1;
static int progress_drawn = 0;

void rawstor_cli_progress(int percent) {
    if (isatty(STDERR_FILENO)) {
        fprintf(stderr, "\r%3d%%", percent);
        fflush(stderr);
        progress_drawn = 1;
    } else if (percent / 10 > progress_last / 10) {
        fprintf(stderr, "%d%%\n", percent / 10 * 10);
    }
    progress_last = percent;
}

void rawstor_cli_progress_end(void) {
    if (progress_drawn) {
        fprintf(stderr, "\r100%%\n");
        progress_drawn = 0;
    }
    progress_last = -1;
}

int rawstor_cli_export(const char* target, const char* path) {
    fprintf(stderr, "Exporting %s to %s\n", target, path);

    RawstorCliOp op;
    int res = rawstor_cli_op_init(&op);
    if (res < 0) {
        fprintf(stderr, "Failed to create queue: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    op.on_progress = rawstor_cli_progress;
    int sres = rawstor_target_export(
        op.queue, target, path, rawstor_cli_op_progress_cb, &op
    );
    ssize_t result = rawstor_cli_op_wait(&op, sres);
    rawstor_cli_op_destroy(&op);
    rawstor_cli_progress_end();
    if (result < 0) {
        fprintf(
            stderr, "rawstor_target_export() failed: %s\n",
            strerror((int)-result)
        );
        return rawstd_exitcode_for_errno((int)-result);
    }

    fprintf(stderr, "Exported\n");
    return 0;
}
