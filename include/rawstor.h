#ifndef _RAWSTOR_H_
#define _RAWSTOR_H_

#include <sys/types.h>
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
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data);

int rawstor_fd_readv(
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data);

int rawstor_fd_write(
    int fd, off_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data);

int rawstor_fd_writev(
    int fd, off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data);

RawstorAIOEvent* rawstor_event_wait(void);

RawstorAIOEvent* rawstor_event_wait_timeout(int timeout);

int rawstor_event_dispatch(RawstorAIOEvent *event);

void rawstor_event_release(RawstorAIOEvent *event);


/**
 * Volume
 */

typedef struct RawstorVolume RawstorVolume;

struct RawstorVolumeSpec {
    size_t size;
};

typedef int(*rawstor_cb)(RawstorVolume *volume, void *data);


int rawstor_create(struct RawstorVolumeSpec spec, int *volume_id);

int rawstor_delete(int volume_id);

int rawstor_open(int volume_id, RawstorVolume **volume);

int rawstor_close(RawstorVolume *volume);

int rawstor_spec(int volume_id, struct RawstorVolumeSpec *spec);

int rawstor_read(
    RawstorVolume *volume,
    off_t offset,
    void *buf, size_t size,
    rawstor_cb cb, void *data);

int rawstor_readv(
    RawstorVolume *volume,
    off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_cb cb, void *data);

int rawstor_write(
    RawstorVolume *volume,
    off_t offset,
    void *buf, size_t size,
    rawstor_cb cb, void *data);

int rawstor_writev(
    RawstorVolume *volume,
    off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_cb cb, void *data);


#endif // _RAWSTOR_H_
