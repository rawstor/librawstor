#include "show.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int rawstor_cli_show(const char* uris) {
    struct RawstorObjectSpec spec;
    int res = rawstor_object_spec(uris, &spec);
    if (res) {
        fprintf(stderr, "rawstor_object_spec() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    printf("uri: %s\n", uris);
    printf("size: %zu Gb\n", spec.size >> 30);

    return EXIT_SUCCESS;
}
