#include "server.h"

#include "protocol.h"

#include <rawstor.h>

#include <liburing.h>

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#define QUEUE_DEPTH 256

/* The version of the protocol we support */
#define VHOST_USER_VERSION 1


typedef enum {
    EVENT_READ = 1,
    EVENT_WRITE = 2,
} EventType;


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


static RawstorAIOEvent* client_read(
    int socket,
    ssize_t request_size,
    void *buf,
    size_t size);


static RawstorAIOEvent* client_write(
    int socket,
    ssize_t response_size,
    void *buf,
    size_t size);


static RawstorAIOEvent* client_read(
    int socket,
    ssize_t request_size,
    void *buf,
    size_t)
{
    if (request_size == 0) {
        printf("Connection lost: %d\n", socket);
        free(buf);
        return NULL;
    } else if (
        request_size < (int)VHOST_USER_HDR_SIZE ||
        request_size > (int)sizeof(VhostUserMsg)
    ) {
        printf("Unexpected request size: %ld\n", request_size);
        free(buf);
        return NULL;
    }

    int response = 0;
    VhostUserMsg *msg = buf;

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
        if(close(socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", socket);
        }
        free(msg);
        return NULL;
    }

    msg->flags = VHOST_USER_VERSION |
                 VHOST_USER_REPLY_MASK;

    RawstorAIOEvent *event = rawstor_fd_write(
        socket, 0,
        msg, VHOST_USER_HDR_SIZE + msg->size);
    if (event == NULL) {
        perror("rawstor_fd_write() failed");
        int errsv = errno;
        if(close(socket)) {
            perror("close() failed");
        } else {
            printf("Connection closed: %d\n", socket);
        }
        free(msg);
        errno = errsv;
        return NULL;
    }
    rawstor_aio_event_set_data(event, (void*)EVENT_WRITE);

    return event;
}


static RawstorAIOEvent* client_write(
    int socket,
    ssize_t response_size,
    void *buf,
    size_t size)
{
    printf("Message sent: %ld bytes\n", response_size);

    RawstorAIOEvent *event = rawstor_fd_read(socket, 0, buf, size);
    if (event == NULL) {
        perror("rawstor_fd_read() failed");
        return NULL;
    }
    rawstor_aio_event_set_data(event, (void*)EVENT_READ);
    return event;
}


static RawstorAIOEvent* server_accept(int client_socket) {
    void *msg = malloc(sizeof(VhostUserMsg));
    if (msg == NULL) {
        perror("malloc() failed");
        int errsv = errno;
        if(close(client_socket)) {
            perror("close() failed");
        }
        errno = errsv;
        return NULL;
    }

    RawstorAIOEvent *event = rawstor_fd_read(
        client_socket, 0,
        msg, sizeof(VhostUserMsg));
    if (event == NULL) {
        perror("rawstor_fd_read() failed");
        int errsv = errno;
        if(close(client_socket)) {
            perror("close() failed");
        }
        errno = errsv;
        return NULL;
    }
    rawstor_aio_event_set_data(event, (void*)EVENT_READ);

    printf("Connection opened: %d\n", client_socket);

    return event;
}


static RawstorAIOEvent* server_dispatch(RawstorAIOEvent *event) {
    int client_socket = rawstor_aio_event_res(event);
    if (client_socket == -1) {
        fprintf(stderr, "accept() failed\n");
        return NULL;
    }

    return server_accept(client_socket);
}


static RawstorAIOEvent* client_dispatch(RawstorAIOEvent *event) {
    EventType et = (EventType)rawstor_aio_event_get_data(event);
    int client_socket = rawstor_aio_event_fd(event);
    ssize_t response_size = rawstor_aio_event_res(event);
    void *buf = rawstor_aio_event_buf(event);
    size_t size = rawstor_aio_event_size(event);

    switch (et) {
        case EVENT_READ:
            if (response_size == -1) {
                fprintf(stderr, "read() failed\n");
                return NULL;
            }
            return client_read(client_socket, response_size, buf, size);
            break;
        case EVENT_WRITE:
            if (response_size == -1) {
                fprintf(stderr, "write() failed\n");
                return NULL;
            }
            return client_write(client_socket, response_size, buf, size);
            break;
        default:
            printf("Unexpected event type\n");
    }

    return NULL;
}


static int server_loop(int server_socket) {
    if (rawstor_initialize()) {
        perror("rawstor_initialize() failed");
        return -1;
    };

    RawstorAIOEvent *accept_event = rawstor_fd_accept(server_socket);
    if (accept_event == NULL) {
        perror("rawstor_fd_accept() failed");
        return -errno;
    }

    RawstorAIOEvent *client_event = NULL;

    while (1) {
        printf("Waiting for event...\n");
        RawstorAIOEvent *event = rawstor_wait_event();
        if (event == NULL) {
            perror("rawstor_wait_event() failed");
            break;
        }

        printf("Dispatching event...\n");
        if (event == accept_event) {
            client_event = server_dispatch(event);
            if (client_event == NULL) {
                printf("server_accept() failed\n");
                rawstor_release_event(event);
                break;
            }
        } else if (event == client_event) {
            client_event = client_dispatch(event);
            if (client_event == NULL) {
                printf("client_dispatch() failed\n");
                rawstor_release_event(event);
                break;
            }
        } else {
            if (rawstor_dispatch_event(event)) {
                rawstor_release_event(event);
                break;
            }
        }

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
