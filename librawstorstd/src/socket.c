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
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -errno;
    }

    if (flags & flag) {
        return 0;
    }

    flags = flags | flag;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        return -errno;
    }

    return 0;
}


int rawstor_socket_set_nonblock(int fd) {
    if (socket_add_flag(fd, O_NONBLOCK)) {
        return -errno;
    }

    rawstor_info("fd %d: O_NONBLOCK\n", fd);

    return 0;
}

int rawstor_socket_set_nodelay(int fd) {
    int onoff = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &onoff, sizeof(onoff))) {
        return -errno;
    }

    rawstor_info("fd %d: IPPROTO_TCP/TCP_NODELAY\n", fd);

    return 0;
}


int rawstor_socket_set_snd_timeout(int fd, unsigned int timeout) {
    struct timeval timeo = {
        .tv_sec = timeout / 1000,
        .tv_usec = (timeout % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo))) {
        return -errno;
    }

    rawstor_info("fd %d: SOL_SOCKET/SO_SNDTIMEO = %ums\n", fd, timeout);

    return 0;
}


int rawstor_socket_set_rcv_timeout(int fd, unsigned int timeout) {
    struct timeval timeo = {
        .tv_sec = timeout / 1000,
        .tv_usec = (timeout % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo))) {
        return -errno;
    }

    rawstor_info("fd %d: SOL_SOCKET/SO_RCVTIMEO = %ums\n", fd, timeout);

    return 0;
}


int rawstor_socket_set_user_timeout(int fd, unsigned int timeout) {
    #if defined(RAWSTOR_ON_LINUX)
        if (setsockopt(
            fd, IPPROTO_TCP, TCP_USER_TIMEOUT,
            &timeout, sizeof(timeout)))
        {
            return -errno;
        }
        rawstor_info("fd %d: IPPROTO_TCP/TCP_USER_TIMEOUT = %ums\n", fd, timeout);
    #elif defined(RAWSTOR_ON_MACOS)
        timeout /= 1000;
        if (setsockopt(
            fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT,
            &timeout, sizeof(timeout)))
        {
            return -errno;
        }
        rawstor_info(
            "fd %d: IPPROTO_TCP/TCP_CONNECTIONTIMEOUT = %us\n", fd, timeout);
    #else
        #error "Unexpected platform"
    #endif

    return 0;
}


int rawstor_socket_set_snd_bufsize(int fd, unsigned int size) {
    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size))) {
        return -errno;
    }

    rawstor_info("fd %d: SOL_SOCKET/SO_SNDBUF = %ub\n", fd, size);

    return 0;
}


int rawstor_socket_set_rcv_bufsize(int fd, unsigned int size) {
    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size))) {
        return -errno;
    }

    rawstor_info("fd %d: SOL_SOCKET/SO_RCVBUF = %ub\n", fd, size);

    return 0;
}
