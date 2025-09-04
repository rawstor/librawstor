#include "connection_ost.h"

#include "opts.h"
#include "ost_protocol.h"

#include <rawstorio/queue.h>

#include <rawstorstd/logging.h>
#include <rawstorstd/socket.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>


struct RawstorConnection {
    int *fds;
    size_t nfds;
};


static int ost_connect(const struct RawstorSocketAddress *ost) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return -errno;
    }

    unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
    if (so_sndtimeo != 0) {
        if (rawstor_socket_set_snd_timeout(fd, so_sndtimeo)) {
            return -errno;
        }
    }

    unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
    if (so_rcvtimeo != 0) {
        if (rawstor_socket_set_rcv_timeout(fd, so_rcvtimeo)) {
            return -errno;
        }
    }

    unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
    if (tcp_user_timeo != 0) {
        if (rawstor_socket_set_user_timeout(fd, tcp_user_timeo)) {
            return -errno;
        }
    }

    struct sockaddr_in servaddr = {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(ost->host);
    servaddr.sin_port = htons(ost->port);

    rawstor_info("Connecting to %s:%u\n", ost->host, ost->port);
    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        return -errno;
    }

    return fd;
}


/**
 * TODO: Do it async or solve partial IO issue.
 */
static int ost_set_object_id(int fd, const struct RawstorUUID *object_id) {
    RawstorOSTFrameBasic request_frame = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
    };
    memcpy(
        request_frame.obj_id,
        object_id->bytes,
        sizeof(request_frame.obj_id));

    int res = write(fd, &request_frame, sizeof(request_frame));
    if (res < 0) {
        return -errno;
    }
    assert(res == sizeof(request_frame));

    RawstorOSTFrameResponse response_frame;
    res = read(fd, &response_frame, sizeof(response_frame));
    if (res < 0) {
        return -errno;
    }
    assert(res == sizeof(response_frame));

    if (response_frame.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "Unexpected magic number: %x != %x\n",
            response_frame.magic, RAWSTOR_MAGIC);
        errno = EPROTO;
        return -errno;
    }

    if (response_frame.res < 0) {
        rawstor_error(
            "Server failed to set object id: %s\n",
            strerror(-response_frame.res));
        errno = EPROTO;
        return -errno;
    }

    if (response_frame.cmd != RAWSTOR_CMD_SET_OBJECT) {
        rawstor_error(
            "Unexpected command in response: %d\n",
            response_frame.cmd);
        errno = EPROTO;
        return -errno;
    }

    if (rawstor_io_queue_setup_fd(fd)) {
        return -errno;
    }

    return 0;
}


RawstorConnection* rawstor_connection_create(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    size_t count)
{
    RawstorConnection *cn = malloc(sizeof(RawstorConnection));
    if (cn == NULL) {
        goto err_cn;
    }

    cn->fds = calloc(count, sizeof(int));
    if (cn->fds) {
        goto err_fds;
    }
    cn->nfds = count;
    for (size_t i = 0; i < cn->nfds; ++i) {
        cn->fds[i] = -1;
    }

    for (size_t i = 0; i < cn->nfds; ++i) {
        cn->fds[i] = ost_connect(ost);
        if (cn->fds[i] < 0) {
            goto err_connect;
        }

        if (ost_set_object_id(cn->fds[i], object_id)) {
            goto err_set_object_id;
        }
    }

    return cn;

    int errsv;
err_set_object_id:
err_connect:
    errsv = errno;
    for (size_t i = 0; i < cn->nfds; ++i) {
        if (cn->fds[i] >= 0) {
            close(cn->fds[i]);
            cn->fds[i] = -1;
        }
    }
    errno = errsv;
err_fds:
    free(cn->fds);
err_cn:
    return NULL;
}


int rawstor_connection_delete(RawstorConnection *cn) {
    for (size_t i = 0; i < cn->nfds; ++i) {
        if (cn->fds[i] >= 0) {
            int rval = close(cn->fds[i]);
            if (rval == -1) {
                return -errno;
            }
            cn->fds[i] = -1;
        }
    }

    free(cn->fds);
    free(cn);

    return 0;
}
