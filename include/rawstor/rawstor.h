/**
 * Copyright (C) 2025, Vasily Stepanov (vasily.stepanov@gmail.com)
 *
 * SPDX-License-Identifier: LGPL-3.0
 */

#ifndef RAWSTOR_RAWSTOR_H
#define RAWSTOR_RAWSTOR_H

#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef int(RawstorIOCallback)(size_t result, int error, void* data);

/**
 * fd
 */

int rawstor_fd_poll(
    int fd, unsigned int mask, RawstorIOCallback* cb, void* data
);

int rawstor_fd_read(
    int fd, void* buf, size_t size, RawstorIOCallback* cb, void* data
);

int rawstor_fd_readv(
    int fd, struct iovec* iov, unsigned int niov, RawstorIOCallback* cb,
    void* data
);

int rawstor_fd_pread(
    int fd, void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
);

int rawstor_fd_preadv(
    int fd, struct iovec* iov, unsigned int niov, off_t offset,
    RawstorIOCallback* cb, void* data
);

int rawstor_fd_recv(
    int fd, void* buf, size_t size, unsigned int flags, RawstorIOCallback* cb,
    void* data
);

int rawstor_fd_recvmsg(
    int fd, struct msghdr* msg, unsigned int flags, RawstorIOCallback* cb,
    void* data
);

int rawstor_fd_write(
    int fd, const void* buf, size_t size, RawstorIOCallback* cb, void* data
);

int rawstor_fd_writev(
    int fd, const struct iovec* iov, unsigned int niov, RawstorIOCallback* cb,
    void* data
);

int rawstor_fd_pwrite(
    int fd, const void* buf, size_t size, off_t offset, RawstorIOCallback* cb,
    void* data
);

int rawstor_fd_pwritev(
    int fd, const struct iovec* iov, unsigned int niov, off_t offset,
    RawstorIOCallback* cb, void* data
);

int rawstor_fd_send(
    int fd, const void* buf, size_t size, unsigned int flags,
    RawstorIOCallback* cb, void* data
);

int rawstor_fd_sendmsg(
    int fd, const struct msghdr* msg, unsigned int flags, RawstorIOCallback* cb,
    void* data
);

/**
 * Lib
 */

struct RawstorOpts {
    unsigned int wait_timeout;
    unsigned int io_attempts;
    unsigned int sessions;
    unsigned int so_sndtimeo;
    unsigned int so_rcvtimeo;
    unsigned int tcp_user_timeout;
};

int rawstor_initialize(const struct RawstorOpts* opts);

void rawstor_terminate(void);

int rawstor_wait(void);

#ifdef __cplusplus
}
#endif

#endif // RAWSTOR_RAWSTOR_H
