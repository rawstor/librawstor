#ifndef RAWSTOR_H
#define RAWSTOR_H

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

RawstorAIOEvent* rawstor_wait_event(void);

RawstorAIOEvent* rawstor_wait_event_timeout(int timeout);

int rawstor_dispatch_event(RawstorAIOEvent *event);

void rawstor_release_event(RawstorAIOEvent *event);

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


/**
 * Object
 */

typedef struct RawstorObject RawstorObject;

struct RawstorObjectSpec {
    size_t size;
};

typedef int(*rawstor_cb)(RawstorObject *object, void *data);


int rawstor_object_create(struct RawstorObjectSpec spec, int *object_id);

int rawstor_object_delete(int object_id);

int rawstor_object_open(int object_id, RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(int object_id, struct RawstorObjectSpec *spec);

int rawstor_object_read(
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_cb cb, void *data);

int rawstor_object_readv(
    RawstorObject *object,
    off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_cb cb, void *data);

int rawstor_object_write(
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_cb cb, void *data);

int rawstor_object_writev(
    RawstorObject *object,
    off_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_cb cb, void *data);


#endif // RAWSTOR_H
