#include "show.h"

#include "units.h"

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

    char buf[256];
    rawstor_cli_bytes_to_size(spec.size, buf, sizeof(buf));

    printf("uri: %s\n", uris);
    printf("size: %s\n", buf);

    return EXIT_SUCCESS;
}
