#include "show.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_show(const char **uris, size_t nuris) {
    struct RawstorObjectSpec spec;
    int res = rawstor_object_spec(uris, nuris, &spec);
    if (res) {
        fprintf(stderr, "rawstor_object_spec() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    for (size_t i = 0; i < nuris; ++i) {
        printf("uri: %s\n", uris[i]);
    }
    printf("size: %zu Gb\n", spec.size >> 30);

    return EXIT_SUCCESS;
}
