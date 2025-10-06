#include "server.h"

#include "protocol.h"

#include <rawstorstd/gcc.h>

#include <rawstor.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


#define QUEUE_DEPTH 256

/* The version of the protocol we support */
#define VHOST_USER_VERSION 1


static int get_features(VhostUserMsg *msg) {
    msg->payload.u64 =
        /*
         * The following VIRTIO feature bits are supported by our virtqueue
         * implementation:
         */
        1ULL << VIRTIO_F_NOTIFY_ON_EMPTY |
        1ULL << VIRTIO_RING_F_INDIRECT_DESC |
        1ULL << VIRTIO_RING_F_EVENT_IDX |
        1ULL << VIRTIO_F_VERSION_1 |

        /* vhost-user feature bits */
        1ULL << VHOST_F_LOG_ALL |
        1ULL << VHOST_USER_F_PROTOCOL_FEATURES;

    msg->size = sizeof(msg->payload.u64);
    msg->fd_num = 0;

    printf("Sending back to guest u64: 0x%016"PRIx64"\n", msg->payload.u64);

    return 1;
}


static int get_protocol_features(VhostUserMsg *msg) {
    /*
     * Note that we support, but intentionally do not set,
     * VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS. This means that
     * a device implementation can return it in its callback
     * (get_protocol_features) if it wants to use this for
     * simulation, but it is otherwise not desirable (if even
     * implemented by the frontend.)
     */
    msg->payload.u64 = 1ULL << VHOST_USER_PROTOCOL_F_MQ |
                       1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD |
                       1ULL << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
                       1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER |
                       1ULL << VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD |
                       1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK |
                       1ULL << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
                       1ULL << VHOST_USER_PROTOCOL_F_CONFIG;

    msg->payload.u64 &= ~(1ULL << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD);

    msg->size = sizeof(msg->payload.u64);
    msg->fd_num = 0;

    printf("Sending back to guest u64: 0x%016"PRIx64"\n", msg->payload.u64);

    return 1;
}


static int dispatch_vu_request(VhostUserMsg *msg) {
    printf("Request: %d\n", msg->request);
    printf("Flags:   0x%x\n", msg->flags);
    printf("Size:    %u\n", msg->size);

    switch (msg->request) {
        case VHOST_USER_GET_FEATURES:
            return get_features(msg);
        case VHOST_USER_GET_PROTOCOL_FEATURES:
            return get_protocol_features(msg);
        default:
            printf("Unexpected request: %d\n", msg->request);
    };
    return 0;
}


static int server_read(RawstorIOEvent *event, void *data);


static int server_write(RawstorIOEvent *event, void *data);


static int server_read(RawstorIOEvent *event, void *data) {
    int client_socket = rawstor_io_event_fd(event);
    VhostUserMsg *msg = (VhostUserMsg*)data;

    int error = rawstor_io_event_error(event);
    if (error != 0) {
        fprintf(stderr, "read() failed: %s\n", strerror(error));
        return -error;
    }

    size_t result = rawstor_io_event_result(event);
    if (result == 0) {
        fprintf(
            stderr,
            "Connection lost: %d\n", client_socket);
        return 0;
    } else if (
        result < (int)VHOST_USER_HDR_SIZE ||
        result > (int)sizeof(VhostUserMsg)
    ) {
        fprintf(
            stderr,
            "Unexpected request size: %zu\n", result);
        return -EPROTO;
    }

    int response = 0;

    printf("============= Vhost user message =============\n");
    response = dispatch_vu_request(msg);
    printf("==============================================\n");

    if (!response &&
        msg->flags & VHOST_USER_NEED_REPLY_MASK)
    {
        msg->payload.u64 = 0;
        msg->size = sizeof(msg->payload.u64);
        msg->fd_num = 0;
        response = 1;
    }

    if (!response) {
        return 0;
    }

    msg->flags = VHOST_USER_VERSION |
                 VHOST_USER_REPLY_MASK;

    int res = rawstor_fd_write(
        client_socket, msg, VHOST_USER_HDR_SIZE + msg->size,
        server_write, msg);
    if (res)
    {
        fprintf(stderr, "rawstor_fd_write() failed: %s\n", strerror(-res));
        return res;
    }

    return 0;
}


static int server_write(RawstorIOEvent *event, void *data) {
    int client_socket = rawstor_io_event_fd(event);
    VhostUserMsg *msg = (VhostUserMsg*)data;

    int error = rawstor_io_event_error(event);
    if (error != 0) {
        fprintf(stderr, "write() failed: %s\n", strerror(error));
        return -error;
    }

    printf("Message sent: %ld bytes\n", rawstor_io_event_result(event));

    int res = rawstor_fd_read(
        client_socket, msg, rawstor_io_event_size(event),
        server_read, msg);
    if (res) {
        fprintf(stderr, "rawstor_fd_read() failed: %s\n", strerror(-res));
        return res;
    }

    return 0;
}


static int server_loop(int client_socket) {
    int res = rawstor_initialize(NULL);
    if (res) {
        fprintf(stderr, "rawstor_initialize() failed: %s\n", strerror(-res));
        return res;
    };

    VhostUserMsg msg;

    res = rawstor_fd_read(
        client_socket, &msg, sizeof(VhostUserMsg),
        server_read, &msg);
    if (res) {
        fprintf(stderr, "rawstor_fd_read() failed: %s\n", strerror(-res));
        return res;
    }

    int rval = 0;
    while (!rval) {
        printf("Waiting for event...\n");
        RawstorIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            if (errno) {
                perror("rawstor_wait_event() failed");
                errno = 0;
            } else {
                printf("EOF\n");
            }
            break;
        }

        printf("Dispatching event...\n");
        rval = rawstor_dispatch_event(event);

        rawstor_release_event(event);
    }

    rawstor_terminate();

    return 0;
}


int rawstor_vu_server(
    const char RAWSTOR_UNUSED *uri,
    int RAWSTOR_UNUSED object_id,
    const char *socket_path)
{
    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("socket() failed");
        return -1;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX
    };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind() failed");
        if (close(server_socket)) {
            err(EXIT_FAILURE, NULL);
        }
        return -1;
    }

    if (listen(server_socket, 1)) {
        perror("listen() failed");
        if (unlink(addr.sun_path)) {
            err(EXIT_FAILURE, NULL);
        }
        if (close(server_socket)) {
            err(EXIT_FAILURE, NULL);
        }
        return -1;
    }

    int client_socket = accept(server_socket, NULL, NULL);
    if (client_socket < 0) {
        perror("accept() failed");
        if (unlink(addr.sun_path)) {
            err(EXIT_FAILURE, NULL);
        }
        if (close(server_socket)) {
            err(EXIT_FAILURE, NULL);
        }
        return -errno;
    }
    printf("Connection opened: %d\n", client_socket);

    int rval = server_loop(client_socket);

    if(close(client_socket)) {
        perror("close() failed");
    } else {
        printf("Connection closed: %d\n", client_socket);
    }

    if (unlink(socket_path)) {
        perror("unlink() failed");
        if (close(server_socket)) {
            err(EXIT_FAILURE, NULL);
        }
        return -1;
    }

    if (close(server_socket)) {
        perror("close() failed");
        return -1;
    }

    return rval;
}
