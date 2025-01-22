#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <sys/uio.h>

#include <stddef.h>


/**
 * AIO
 */

typedef struct RawstorAIOEvent RawstorAIOEvent;


/**
 * Lib
 */

int rawstor_initialize(void);

void rawstor_terminate(void);

typedef int(*rawstor_fd_cb)(
    int fd,
    ssize_t rval,
    void *buf,
    size_t size);


int rawstor_fd_accept(int fd, rawstor_fd_cb cb);

int rawstor_fd_read(
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_fd_cb cb);

int rawstor_fd_write(
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_fd_cb cb);

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

int rawstor_aio_event_fd(RawstorAIOEvent *event);


#endif // _RAWSTOR_H_
