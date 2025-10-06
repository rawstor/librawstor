#include "show.h"

#include "gcc.h"

#include <rawstor.h>

#include <assert.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int rawstor_cli_show(const char *uri) {
    struct RawstorObjectSpec spec;
    int res = rawstor_object_spec(uri, &spec);
    if (res) {
        fprintf(stderr, "rawstor_object_spec() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    printf("size: %zu Gb\n", spec.size >> 30);

    return EXIT_SUCCESS;
}
