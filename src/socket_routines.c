#include "socket_routines.h"

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
    return socket_add_flag(fd, O_NONBLOCK);
}
