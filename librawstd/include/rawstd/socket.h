#ifndef RAWSTD_SOCKET_ROUTINES_H
#define RAWSTD_SOCKET_ROUTINES_H

#include "rawstd/gcc.h"

#include <sys/socket.h>

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
