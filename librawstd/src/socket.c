#include "rawstd/socket.h"

#include "rawstd/gcc.h"
#include "rawstd/logging.h"

#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include <sys/socket.h>
#include <sys/types.h>

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>

int rawstd_socket_resolve_all(
    const char* host, unsigned int port, struct sockaddr_in* addrs,
    size_t* count
) {
    struct addrinfo hints = {
        .ai_family = AF_INET,
        .ai_socktype = SOCK_STREAM,
    };
    struct addrinfo* res = NULL;

    char service[8];
    if (port > 65535) {
        return -EINVAL;
    }
    snprintf(service, sizeof(service), "%u", port);

    int ret = getaddrinfo(host, service, &hints, &res);
    if (ret != 0) {
        switch (ret) {
        case EAI_SYSTEM: {
            int error = errno;
            errno = 0;
            return error != 0 ? -error : -EIO;
        }
        case EAI_AGAIN:
            return -EAGAIN;
        case EAI_MEMORY:
            return -ENOMEM;
        default:
            rawstd_warning(
                "Failed to resolve %s: %s\n", host, gai_strerror(ret)
            );
            return -EINVAL;
        }
    }

    size_t n = 0;
    for (struct addrinfo* ai = res; ai != NULL && n < *count;
         ai = ai->ai_next) {
        if (ai->ai_addrlen != sizeof(*addrs)) {
            continue;
        }
        memcpy(&addrs[n], ai->ai_addr, sizeof(*addrs));
        ++n;
    }
    freeaddrinfo(res);

    if (n == 0) {
        return -EINVAL;
    }
    *count = n;

    return 0;
}

int rawstd_socket_resolve(
    const char* host, unsigned int port, struct sockaddr_in* addr
) {
    size_t count = 1;
    return rawstd_socket_resolve_all(host, port, addr, &count);
}

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

int rawstd_socket_set_nonblock(int fd) {
    int res = socket_add_flag(fd, O_NONBLOCK);
    if (res) {
        return res;
    }

    rawstd_debug("fd %d: O_NONBLOCK\n", fd);

    return 0;
}

int rawstd_socket_set_cloexec(int fd) {
    int error;

    if (fcntl(fd, F_SETFD, FD_CLOEXEC) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: FD_CLOEXEC\n", fd);

    return 0;
}

int rawstd_socket_set_nodelay(int fd) {
    int error;

    int onoff = 1;
    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &onoff, sizeof(onoff)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: IPPROTO_TCP/TCP_NODELAY\n", fd);

    return 0;
}

int rawstd_socket_set_nosigpipe(int fd) {
#if defined(RAWSTD_ON_LINUX)
    // Linux suppresses SIGPIPE per-call via MSG_NOSIGNAL on send()/sendmsg()
    // instead; nothing to set on the socket itself.
    (void)fd;
    return 0;
#elif defined(RAWSTD_ON_MACOS)
    int error;

    int onoff = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &onoff, sizeof(onoff)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: SOL_SOCKET/SO_NOSIGPIPE\n", fd);

    return 0;
#else
#error "Unexpected platform"
#endif
}

int rawstd_socket_set_reuse(int fd) {
    int error;

    int onoff = 1;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &onoff, sizeof(onoff)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: SOL_SOCKET/SO_REUSEADDR\n", fd);

    return 0;
}

int rawstd_socket_set_snd_timeout(int fd, unsigned int timeout) {
    int error;

    struct timeval timeo = {
        .tv_sec = timeout / 1000,
        .tv_usec = (timeout % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &timeo, sizeof(timeo)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: SOL_SOCKET/SO_SNDTIMEO = %ums\n", fd, timeout);

    return 0;
}

int rawstd_socket_set_rcv_timeout(int fd, unsigned int timeout) {
    int error;

    struct timeval timeo = {
        .tv_sec = timeout / 1000,
        .tv_usec = (timeout % 1000) * 1000,
    };
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeo, sizeof(timeo)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: SOL_SOCKET/SO_RCVTIMEO = %ums\n", fd, timeout);

    return 0;
}

int rawstd_socket_set_user_timeout(int fd, unsigned int timeout) {
    int error;

#if defined(RAWSTD_ON_LINUX)
    if (setsockopt(
            fd, IPPROTO_TCP, TCP_USER_TIMEOUT, &timeout, sizeof(timeout)
        ) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }
    rawstd_debug("fd %d: IPPROTO_TCP/TCP_USER_TIMEOUT = %ums\n", fd, timeout);
#elif defined(RAWSTD_ON_MACOS)
    timeout = (timeout + 999) / 1000;
    if (setsockopt(
            fd, IPPROTO_TCP, TCP_CONNECTIONTIMEOUT, &timeout, sizeof(timeout)
        ) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }
    rawstd_debug(
        "fd %d: IPPROTO_TCP/TCP_CONNECTIONTIMEOUT = %us\n", fd, timeout
    );
#else
#error "Unexpected platform"
#endif

    return 0;
}

int rawstd_socket_set_snd_bufsize(int fd, unsigned int size) {
    int error;

    if (setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, sizeof(size)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: SOL_SOCKET/SO_SNDBUF = %u bytes\n", fd, size);

    return 0;
}

int rawstd_socket_set_rcv_bufsize(int fd, unsigned int size) {
    int error;

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size)) == -1) {
        error = errno;
        errno = 0;
        return -error;
    }

    rawstd_debug("fd %d: SOL_SOCKET/SO_RCVBUF = %u bytes\n", fd, size);

    return 0;
}
