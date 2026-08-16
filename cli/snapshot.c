#include "snapshot.h"

#include <rawstor.h>

#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_snapshot(const char* target) {
    fprintf(stderr, "Snapshotting volume: %s\n", target);

    uint64_t snap_id = 0;
    int res = rawstor_volume_snapshot(target, &snap_id);
    if (res) {
        fprintf(
            stderr, "rawstor_volume_snapshot() failed: %s\n", strerror(-res)
        );
        return EXIT_FAILURE;
    }

    fprintf(
        stderr, "Snapshot created; read it as %s@%" PRIu64 "\n", target, snap_id
    );
    fprintf(stdout, "%" PRIu64 "\n", snap_id);

    return EXIT_SUCCESS;
}

int rawstor_cli_snap_remove(const char* target, uint64_t snap_id) {
    fprintf(
        stderr, "Removing snapshot %" PRIu64 " of volume: %s\n", snap_id, target
    );

    int res = rawstor_volume_snap_remove(target, snap_id);
    if (res) {
        fprintf(
            stderr, "rawstor_volume_snap_remove() failed: %s\n", strerror(-res)
        );
        return EXIT_FAILURE;
    }

    fprintf(stderr, "Snapshot removed\n");

    return EXIT_SUCCESS;
}
