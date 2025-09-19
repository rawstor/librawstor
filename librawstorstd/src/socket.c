#include "rawstorstd/socket.h"

#include "rawstorstd/gcc.h"
#include "rawstorstd/logging.h"

#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/types.h>
#include <sys/socket.h>

#include <errno.h>
#include <fcntl.h>


static int socket_add_flag(int fd, int flag) {
    int error;

    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    if (flags & flag) {
        return 0;
    }

    flags = flags | flag;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    return 0;
}


int rawstor_socket_set_nonblock(int fd) {
    int res = socket_add_flag(fd, O_NONBLOCK);
    if (res) {
        return res;
    }

    rawstor_debug("fd %d: O_NONBLOCK\n", fd);

    return 0;
}

int rawstor_socket_set_nodelay(int fd) {
    int error;

    int onoff = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &onoff, sizeof(onoff))) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstor_debug("fd %d: IPPROTO_TCP/TCP_NODELAY\n", fd);

    return 0;
}


int rawstor_socket_set_snd_timeout(int fd, unsigned int timeout) {
    int error;

    struct timeval timeo = {
        .tv_sec = timeout / 1000,
        .tv_usec = (timeout % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo))) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstor_debug("fd %d: SOL_SOCKET/SO_SNDTIMEO = %ums\n", fd, timeout);

    return 0;
}


int rawstor_socket_set_rcv_timeout(int fd, unsigned int timeout) {
    int error;

    struct timeval timeo = {
        .tv_sec = timeout / 1000,
        .tv_usec = (timeout % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo))) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstor_debug("fd %d: SOL_SOCKET/SO_RCVTIMEO = %ums\n", fd, timeout);

    return 0;
}


int rawstor_socket_set_user_timeout(int fd, unsigned int timeout) {
    int error;

    #if defined(RAWSTOR_ON_LINUX)
        if (setsockopt(
            fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
            &timeout, sizeof(timeout)))
        {
            error = errno;
            errno = 0;
            return -error;
        }
        rawstor_debug("fd %d: IPPROTO_TCP/TCP_USER_TIMEOUT = %ums\n", fd, timeout);
    #elif defined(RAWSTOR_ON_MACOS)
        timeout = (timeout + 999) / 1000;
        if (setsockopt(
            fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT,
            &timeout, sizeof(timeout)))
        {
            error = errno;
            errno = 0;
            return -error;
        }
        rawstor_debug(
            "fd %d: IPPROTO_TCP/TCP_CONNECTIONTIMEOUT = %us\n", fd, timeout);
    #else
        #error "Unexpected platform"
    #endif

    return 0;
}


int rawstor_socket_set_snd_bufsize(int fd, unsigned int size) {
    int error;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstor_debug("fd %d: SOL_SOCKET/SO_SNDBUF = %u bytes\n", fd, size);

    return 0;
}


int rawstor_socket_set_rcv_bufsize(int fd, unsigned int size) {
    int error;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstor_debug("fd %d: SOL_SOCKET/SO_RCVBUF = %u bytes\n", fd, size);

    return 0;
}
