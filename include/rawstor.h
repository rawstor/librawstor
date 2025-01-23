#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <sys/uio.h>

#include <stddef.h>


/**
 * AIO
 */

typedef struct RawstorAIOEvent RawstorAIOEvent;

typedef int(*rawstor_aio_cb)(RawstorAIOEvent *event, void *data);

int rawstor_aio_event_fd(RawstorAIOEvent *event);

ssize_t rawstor_aio_event_res(RawstorAIOEvent *event);

void* rawstor_aio_event_buf(RawstorAIOEvent *event);

size_t rawstor_aio_event_size(RawstorAIOEvent *event);

struct iovec* rawstor_aio_event_iov(RawstorAIOEvent *event);

unsigned int rawstor_aio_event_niov(RawstorAIOEvent *event);


/**
 * Lib
 */

int rawstor_initialize(void);

void rawstor_terminate(void);


int rawstor_fd_accept(int fd, rawstor_aio_cb cb, void *data);

int rawstor_fd_read(
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data);

int rawstor_fd_readv(
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data);

int rawstor_fd_write(
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data);

int rawstor_fd_writev(
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data);

RawstorAIOEvent* rawstor_wait_event(void);

int rawstor_dispatch_event(RawstorAIOEvent *event);

void rawstor_release_event(RawstorAIOEvent *event);


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
    void *buf);

int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov);


#endif // _RAWSTOR_H_
