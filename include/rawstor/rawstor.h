#ifndef RAWSTOR_RAWSTOR_H
#define RAWSTOR_RAWSTOR_H

#include <rawstor/io_queue.h>
#include <rawstor/uuid.h>

#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif


/**
 * fd
 */

int rawstor_fd_read(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_pread(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_readv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_preadv(
    int fd,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_write(
    int fd, void *buf, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_pwrite(
    int fd, void *buf, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_writev(
    int fd, struct iovec *iov, unsigned int niov, size_t size,
    RawstorIOCallback *cb, void *data);

int rawstor_fd_pwritev(
    int fd, struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorIOCallback *cb, void *data);


/**
 * Lib
 */

struct RawstorOpts {
    unsigned int wait_timeout;
    unsigned int so_sndtimeo;
    unsigned int so_rcvtimeo;
    unsigned int tcp_user_timeout;
};


struct RawstorOptsOST {
    char *host;
    unsigned int port;
};


int rawstor_initialize(
    const struct RawstorOpts *opts,
    const struct RawstorOptsOST *opts_ost);

void rawstor_terminate(void);

RawstorIOEvent* rawstor_wait_event(void);

int rawstor_dispatch_event(RawstorIOEvent *event);

void rawstor_release_event(RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTOR_RAWSTOR_H
