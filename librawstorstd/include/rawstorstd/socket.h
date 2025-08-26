#ifndef RAWSTORSTD_SOCKET_ROUTINES_H
#define RAWSTORSTD_SOCKET_ROUTINES_H


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_socket_set_nonblock(int fd);

int rawstor_socket_set_nodelay(int fd);

int rawstor_socket_set_snd_timeout(int fd, unsigned int timeout);

int rawstor_socket_set_rcv_timeout(int fd, unsigned int timeout);

int rawstor_socket_set_user_timeout(int fd, unsigned int timeout);

int rawstor_socket_set_snd_bufsize(int fd, unsigned int size);

int rawstor_socket_set_rcv_bufsize(int fd, unsigned int size);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORSTD_SOCKET_ROUTINES_H
