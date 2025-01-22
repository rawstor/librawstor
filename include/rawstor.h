#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <sys/uio.h>

#include <stddef.h>


/**
 * AIO
 */

typedef struct RawstorAIO RawstorAIO;

typedef struct RawstorAIOEvent RawstorAIOEvent;

typedef int(*rawstor_aio_cb)(
    RawstorAIO *aio,
    int fd,
    ssize_t rval,
    void *buf,
    size_t size,
    void *arg);


int rawstor_aio_accept(RawstorAIO *aio, int fd, rawstor_aio_cb cb, void *arg);

int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb,
    void *arg);

int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb,
    void *arg);


/**
 * Lib
 */

int rawstor_initialize(void);

void rawstor_terminate(void);

RawstorAIO* rawstor_aio(void);

RawstorAIOEvent* rawstor_get_event(void);

int rawstor_dispatch_event(RawstorAIOEvent *event);


/**
 * Device
 */

typedef struct RawstorDevice RawstorDevice;

struct RawstorDeviceSpec {
    size_t size;
};


int rawstor_create(struct RawstorDeviceSpec spec, int *device_id);

int rawstor_delete(int device_id);

int rawstor_open(int device_id, RawstorDevice **device);

int rawstor_close(RawstorDevice *device);

int rawstor_spec(int device_id, struct RawstorDeviceSpec *spec);

int rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf);

int rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov);

int rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf);

int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov);


#endif // _RAWSTOR_H_
