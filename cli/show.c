#include "show.h"

#include <rawstor.h>

#include <rawstd/exitcode.h>
#include <rawstd/units.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_show(const char* target) {
    struct RawstorObjectSpec spec;
    int res = rawstor_object_spec(target, &spec);
    if (res) {
        fprintf(stderr, "rawstor_object_spec() failed: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    char buf[256];
    rawstd_bytes_to_size(spec.size, buf, sizeof(buf));

    printf("target: %s\n", target);
    printf("size: %s\n", buf);

    return EXIT_SUCCESS;
}
