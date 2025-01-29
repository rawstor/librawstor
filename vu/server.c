#include "server.h"

#include "protocol.h"

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


static int server_read(RawstorAIOEvent *event, void*);


static int server_write(RawstorAIOEvent *event, void*);


static int server_read(RawstorAIOEvent *event, void *) {
    int client_socket = rawstor_aio_event_fd(event);
    ssize_t request_size = rawstor_aio_event_res(event);
    VhostUserMsg *msg = rawstor_aio_event_buf(event);
    if (request_size < 0) {
        fprintf(stderr, "read() failed\n");
        free(msg);
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
        errno = -request_size;
        return -errno;
    } else if (request_size == 0) {
        printf("Connection lost: %d\n", client_socket);
        free(msg);
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
        return 0;
    } else if (
        request_size < (int)VHOST_USER_HDR_SIZE ||
        request_size > (int)sizeof(VhostUserMsg)
    ) {
        printf("Unexpected request size: %ld\n", request_size);
        free(msg);
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
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
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
        free(msg);
        return 0;
    }

    msg->flags = VHOST_USER_VERSION |
                 VHOST_USER_REPLY_MASK;

    if (rawstor_fd_write(
        client_socket, 0,
        msg, VHOST_USER_HDR_SIZE + msg->size,
        server_write, NULL))
    {
        perror("rawstor_fd_write() failed");
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
        free(msg);
        return -1;
    }

    return 0;
}


static int server_write(RawstorAIOEvent *event, void *) {
    int client_socket = rawstor_aio_event_fd(event);
    ssize_t response_size = rawstor_aio_event_res(event);
    VhostUserMsg *msg = rawstor_aio_event_buf(event);
    size_t size = rawstor_aio_event_size(event);

    if (response_size == -1) {
        fprintf(stderr, "write() failed\n");
        free(msg);
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
        return -1;
    }

    printf("Message sent: %ld bytes\n", response_size);

    if (rawstor_fd_read(client_socket, 0, msg, size, server_read, NULL)) {
        perror("rawstor_fd_read() failed");
        if(close(client_socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", client_socket);
        }
        return -1;
    }

    return 0;
}


static int server_accept(RawstorAIOEvent *event, void*) {
    int client_socket = rawstor_aio_event_res(event);
    if (client_socket == -1) {
        int errsv = errno;
        fprintf(stderr, "accept() failed\n");
        errno = errsv;
        return -1;
    }

    void *msg = malloc(sizeof(VhostUserMsg));
    if (msg == NULL) {
        int errsv = errno;
        perror("malloc() failed");
        if(close(client_socket)) {
            perror("close() failed");
        }
        errno = errsv;
        return -1;
    }

    if (rawstor_fd_read(
        client_socket, 0,
        msg, sizeof(VhostUserMsg),
        server_read, NULL))
    {
        int errsv = errno;
        perror("rawstor_fd_read() failed");
        if(close(client_socket)) {
            perror("close() failed");
        }
        errno = errsv;
        return -1;
    }

    printf("Connection opened: %d\n", client_socket);

    return 0;
}


static int server_loop(int server_socket) {
    if (rawstor_initialize()) {
        perror("rawstor_initialize() failed");
        return -1;
    };

    if (rawstor_fd_accept(server_socket, server_accept, NULL)) {
        perror("rawstor_fd_accept() failed");
        return -errno;
    }

    int rval = 0;
    while (!rval) {
        printf("Waiting for event...\n");
        errno = 0;
        RawstorAIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            if (errno) {
                perror("rawstor_wait_event() failed");
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


int rawstor_vu_server(int, const char *socket_path) {
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

    int rval = server_loop(server_socket);

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
