#ifndef _RAWSTOR_AIO_H_
#define _RAWSTOR_AIO_H_

#include <rawstor.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>


typedef struct RawstorAIO RawstorAIO;

typedef struct RawstorAIOEvent RawstorAIOEvent;

typedef int(*rawstor_aio_cb)(RawstorAIOEvent *event, void *data);


RawstorAIO* rawstor_aio_create(unsigned int depth);

void rawstor_aio_delete(RawstorAIO *aio);

/**
 * TODO: Do not support accept function in aio api.
 */
int rawstor_aio_accept(RawstorAIO *aio, int fd, rawstor_aio_cb cb, void *data);

int rawstor_aio_read(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data);

int rawstor_aio_readv(
    RawstorAIO *aio,
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data);

int rawstor_aio_write(
    RawstorAIO *aio,
    int fd, size_t offset,
    void *buf, size_t size,
    rawstor_aio_cb cb, void *data);

int rawstor_aio_writev(
    RawstorAIO *aio,
    int fd, size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_aio_cb cb, void *data);


RawstorAIOEvent* rawstor_aio_wait_event(RawstorAIO *aio);

void rawstor_aio_release_event(RawstorAIO *aio, RawstorAIOEvent *event);

int rawstor_aio_event_fd(RawstorAIOEvent *event);

ssize_t rawstor_aio_event_res(RawstorAIOEvent *event);

void* rawstor_aio_event_buf(RawstorAIOEvent *event);

size_t rawstor_aio_event_size(RawstorAIOEvent *event);

struct iovec* rawstor_aio_event_iov(RawstorAIOEvent *event);

unsigned int rawstor_aio_event_niov(RawstorAIOEvent *event);

int rawstor_aio_event_cb(RawstorAIOEvent *event);


#endif // _RAWSTOR_AIO_H_
