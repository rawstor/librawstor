#include <rawstor.h>

#include <stdio.h>
#include <stdlib.h>


int main() {
    if (rawstor_initialize()) {
        perror("rawstor_create() failed");
        return EXIT_FAILURE;
    }

    struct RawstorDeviceSpec spec = {
        .size = 1 << 30,
    };

    int device_id;
    if (rawstor_create(spec, &device_id)) {
        perror("rawstor_create() failed");
        return EXIT_FAILURE;
    }
    printf("device id: %d\n", device_id);

    rawstor_terminate();
    return EXIT_SUCCESS;
}
