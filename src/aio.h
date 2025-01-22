#ifndef _RAWSTOR_AIO_H_
#define _RAWSTOR_AIO_H_

#include <rawstor.h>

#include <sys/types.h>

#include <stddef.h>


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


RawstorAIO* rawstor_aio_create(unsigned int depth);

void rawstor_aio_delete(RawstorAIO *aio);

RawstorAIOEvent* rawstor_aio_get_event(RawstorAIO *aio);

int rawstor_aio_dispatch_event(RawstorAIO *aio, RawstorAIOEvent *event);

int rawstor_aio_event_fd(RawstorAIOEvent *event);


#endif // _RAWSTOR_AIO_H_
