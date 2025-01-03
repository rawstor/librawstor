#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <stddef.h>


typedef void RawstorDevice;


RawstorDevice* rawstor_alloc(size_t size);

void rawstor_free(RawstorDevice *device);

void rawstor_read(RawstorDevice *device, void *buf, size_t size, size_t offset);

void rawstor_write(RawstorDevice *device, const void *buf, size_t size, size_t offset);


#endif // _RAWSTOR_H_
