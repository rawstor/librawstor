#include <stddef.h>
#include <stdlib.h>
#include <string.h>

#include "rawstor.h"


RawstorDevice* rawstor_alloc(size_t size) {
    return malloc(size);
}

void rawstor_free(RawstorDevice *device) {
    free(device);
}

void rawstor_read(RawstorDevice *device, void *buf, size_t size, size_t offset) {
    memcpy(buf, device + offset, size);
}

void rawstor_write(RawstorDevice *device, const void *buf, size_t size, size_t offset) {
    memcpy(device + offset, buf, size);
}
