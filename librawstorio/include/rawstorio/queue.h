#ifndef RAWSTORIO_QUEUE_H
#define RAWSTORIO_QUEUE_H

#include <rawstor.h>

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdio.h>


#ifdef __cplusplus
extern "C" {
#endif


typedef struct RawstorIOQueue RawstorIOQueue;

// defined in rawstor/io_event.h
// typedef struct RawstorIOEvent RawstorIOEvent;

// defined in rawstor/io_queue.h
// typedef int(RawstorIOCallback)(RawstorIOEvent *event, void *data);


const char* rawstor_io_queue_engine_name(void);

RawstorIOQueue* rawstor_io_queue_create(unsigned int depth);

void rawstor_io_queue_delete(RawstorIOQueue *queue);

int rawstor_io_queue_setup_fd(int fd);

int rawstor_io_queue_read(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_readv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_pread(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_preadv(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_write(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_pwrite(
    RawstorIOQueue *queue,
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_writev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_io_queue_pwritev(
    RawstorIOQueue *queue,
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);


RawstorIOEvent* rawstor_io_queue_wait_event_timeout(
    RawstorIOQueue *queue, unsigned int timeout);

void rawstor_io_queue_release_event(
    RawstorIOQueue *queue, RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_QUEUE_H
