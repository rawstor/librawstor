#ifndef RAWSTOR_H
#define RAWSTOR_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * AIO
 */

typedef struct RawstorAIOEvent RawstorAIOEvent;

typedef int(RawstorAIOCallback)(
    RawstorAIOEvent *event, size_t size, ssize_t res, void *data);


int rawstor_aio_event_fd(RawstorAIOEvent *event);


/**
 * fd
 */

int rawstor_fd_accept(int fd, RawstorAIOCallback *cb, void *data);

int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_readv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_preadv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorAIOCallback *cb, void *data);

int rawstor_sock_recv(
    int sock, void *buf, size_t size, int flags,
    RawstorAIOCallback *cb, void *data);

int rawstor_sock_recvmsg(
    int sock, struct msghdr *message, size_t size, int flags,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorAIOCallback *cb, void *data);

int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorAIOCallback *cb, void *data);

int rawstor_sock_send(
    int sock, void *buf, size_t size, int flags,
    RawstorAIOCallback *cb, void *data);

int rawstor_sock_sendmsg(
    int sock, struct msghdr *message, size_t size, int flags,
    RawstorAIOCallback *cb, void *data);


/**
 * Lib
 */

int rawstor_initialize(void);

void rawstor_terminate(void);

RawstorAIOEvent* rawstor_wait_event(void);

RawstorAIOEvent* rawstor_wait_event_timeout(int timeout);

int rawstor_dispatch_event(RawstorAIOEvent *event);

void rawstor_release_event(RawstorAIOEvent *event);


/**
 * Object
 */

typedef struct RawstorObject RawstorObject;

struct RawstorObjectSpec {
    size_t size;
};

typedef int(RawstorCallback)(
    RawstorObject *object, size_t size, ssize_t res, void *data);


int rawstor_object_create(struct RawstorObjectSpec spec, int *object_id);

int rawstor_object_delete(int object_id);

int rawstor_object_open(int object_id, RawstorObject **object);

int rawstor_object_close(RawstorObject *object);

int rawstor_object_spec(int object_id, struct RawstorObjectSpec *spec);

int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data);

int rawstor_object_pwritev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_H
