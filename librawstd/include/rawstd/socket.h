#ifndef RAWSTD_SOCKET_ROUTINES_H
#define RAWSTD_SOCKET_ROUTINES_H

#include "rawstd/gcc.h"

#include <netinet/in.h>
#include <sys/socket.h>

#include <stddef.h>

#if defined(RAWSTD_ON_LINUX)
#define RAWSTD_MSG_NOSIGNAL MSG_NOSIGNAL
#elif defined(RAWSTD_ON_MACOS)
// macOS has no per-call flag to suppress SIGPIPE on send()/sendmsg();
// rawstd_socket_set_nosigpipe() (SO_NOSIGPIPE) is used instead.
#define RAWSTD_MSG_NOSIGNAL 0
#else
#error "Unexpected platform"
#endif

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Resolves `host` (a dotted IPv4 address or a host name) to its IPv4 socket
 * addresses with `port` (host byte order), in resolver order, storing at most
 * `capacity` of them in `addrs`. Blocks while a name is looked up. Returns the
 * number of addresses stored (at least 1) or a negative errno value.
 */
int rawstd_socket_resolve_all(
    const char* host, unsigned int port, struct sockaddr_in* addrs,
    size_t capacity
);

int rawstd_socket_set_nonblock(int fd);

int rawstd_socket_set_cloexec(int fd);

int rawstd_socket_set_nodelay(int fd);

int rawstd_socket_set_reuse(int fd);

int rawstd_socket_set_nosigpipe(int fd);

int rawstd_socket_set_snd_timeout(int fd, unsigned int timeout);

int rawstd_socket_set_rcv_timeout(int fd, unsigned int timeout);

int rawstd_socket_set_user_timeout(int fd, unsigned int timeout);

int rawstd_socket_set_snd_bufsize(int fd, unsigned int size);

int rawstd_socket_set_rcv_bufsize(int fd, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_SOCKET_ROUTINES_H
