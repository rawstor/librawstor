#ifndef RAWSTD_SOCKET_ROUTINES_H
#define RAWSTD_SOCKET_ROUTINES_H

#ifdef __cplusplus
extern "C" {
#endif

int rawstd_socket_set_nonblock(int fd);

int rawstd_socket_set_nodelay(int fd);

int rawstd_socket_set_reuse(int fd);

int rawstd_socket_set_snd_timeout(int fd, unsigned int timeout);

int rawstd_socket_set_rcv_timeout(int fd, unsigned int timeout);

int rawstd_socket_set_user_timeout(int fd, unsigned int timeout);

int rawstd_socket_set_snd_bufsize(int fd, unsigned int size);

int rawstd_socket_set_rcv_bufsize(int fd, unsigned int size);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_SOCKET_ROUTINES_H
