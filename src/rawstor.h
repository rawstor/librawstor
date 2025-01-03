#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <stddef.h>
#include <sys/uio.h>


typedef void RawstorDevice;


RawstorDevice* rawstor_alloc(size_t size);

void rawstor_free(RawstorDevice *device);

void rawstor_read(
  RawstorDevice *device,
  size_t offset, size_t size,
  void *buf
);

void rawstor_readv(
  RawstorDevice *device,
  size_t offset, size_t size,
  struct iovec *iov, unsigned int niov
);

void rawstor_write(
  RawstorDevice *device,
  size_t offset, size_t size,
  const void *buf
);

void rawstor_writev(
  RawstorDevice *device,
  size_t offset, size_t size,
  const struct iovec *iov, unsigned int niov
);


#endif // _RAWSTOR_H_
