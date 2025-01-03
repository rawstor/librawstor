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


void rawstor_read(
  RawstorDevice *device,
  size_t offset, size_t size,
  void *buf
) {
    memcpy(buf, device + offset, size);
}


void rawstor_readv(
  RawstorDevice *device,
  size_t offset, size_t size,
  struct iovec *iov, unsigned int niov
) {
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        rawstor_read(device, offset, chunk_size, iov[i].iov_base);

        size -= chunk_size;
        offset += chunk_size;
    }
}


void rawstor_write(
  RawstorDevice *device,
  size_t offset, size_t size,
  const void *buf
) {
    memcpy(device + offset, buf, size);
}


void rawstor_writev(
  RawstorDevice *device,
  size_t offset, size_t size,
  const struct iovec *iov, unsigned int niov
) {
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        rawstor_write(device, offset, chunk_size, iov[i].iov_base);

        size -= chunk_size;
        offset += chunk_size;
    }
}
