#include "server.h"

#include "protocol.h"

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
    EVENT_TYPE_ACCEPT,
    EVENT_TYPE_READ,
    EVENT_TYPE_WRITE,
} EventType;


typedef struct {
    EventType event_type;
    int client_socket;
    VhostUserMsg *msg;
} Request;


static int prepare_accept_request(struct io_uring *ring, int server_socket) {
    Request *request = malloc(sizeof(Request));
    if (request == NULL) {
        perror("malloc() failed");
        return -1;
    }
    request->event_type = EVENT_TYPE_ACCEPT;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, server_socket, NULL, NULL, 0);
    io_uring_sqe_set_data(sqe, request);
    return 0;
}


static int prepare_read_request(struct io_uring *ring, int client_socket) {
    Request *request = malloc(sizeof(Request));
    if (request == NULL) {
        perror("malloc() failed");
        return -1;
    }
    request->msg = malloc(sizeof(request->msg));
    if (request->msg == NULL) {
        perror("malloc() failed");
        free(request);
        return -1;
    }
    request->event_type = EVENT_TYPE_READ;
    request->client_socket = client_socket;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(
        sqe,
        client_socket,
        request->msg,
        sizeof(*request->msg),
        0);
    io_uring_sqe_set_data(sqe, request);
    return 0;
}


static int prepare_write_request(
    struct io_uring *ring,
    int client_socket,
    VhostUserMsg *msg)
{
    Request *request = malloc(sizeof(Request));
    if (request == NULL) {
        perror("malloc() failed:");
        return -1;
    }
    request->msg = msg;
    request->event_type = EVENT_TYPE_WRITE;
    request->client_socket = client_socket;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_write(
        sqe,
        client_socket,
        request->msg,
        VHOST_USER_HDR_SIZE + msg->size,
        0);
    io_uring_sqe_set_data(sqe, request);
    return 0;
}


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

    msg->flags &= ~VHOST_USER_VERSION_MASK;
    msg->flags |= VHOST_USER_VERSION;
    msg->flags |= VHOST_USER_REPLY_MASK;

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

    msg->flags &= ~VHOST_USER_VERSION_MASK;
    msg->flags |= VHOST_USER_VERSION;
    msg->flags |= VHOST_USER_REPLY_MASK;

    printf("Sending back to guest u64: 0x%016"PRIx64"\n", msg->payload.u64);

    return 1;
}


static int dispatch_client_request(VhostUserMsg *msg) {
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


static int server_loop(int server_socket) {
    int rval;
    struct io_uring ring;

    rval = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if (rval < 0) {
        fprintf(
            stderr,
            "io_uring_queue_init() failed: %s\n",
            strerror(-rval));
        return -1;
    };

    if (prepare_accept_request(&ring, server_socket)) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    struct io_uring_cqe *cqe;
    while (1) {
        printf("Waiting for event...\n");
        rval = io_uring_submit_and_wait(&ring, 1);
        if (rval < 0) {
            fprintf(
                stderr,
                "io_uring_submit_and_wait() failed: %s\n",
                strerror(-rval));
            if (rval == -EINTR) {
                break;
            }
            // TODO: Fatal error here?
            continue;
        }
        rval = io_uring_peek_cqe(&ring, &cqe);
        if (rval < 0) {
            fprintf(
                stderr,
                "io_uring_peek_cqe() failed: %s\n",
                strerror(-rval));
            if (rval == -EINTR) {
                break;
            }
            // TODO: Fatal error here?
            continue;
        }

        Request *request = (Request*)io_uring_cqe_get_data(cqe);
        printf("Event received: %d\n", request->event_type);
        if (cqe->res < 0) {
            fprintf(
                stderr,
                "io_uring request failed for event %d: %s\n",
                request->event_type,
                strerror(-cqe->res));
            free(request);
            io_uring_cqe_seen(&ring, cqe);
            // TODO: Fatal error here?
            continue;
        }

        switch (request->event_type) {
            case EVENT_TYPE_ACCEPT:
                printf("Connection opened: %d\n", cqe->res);
                if (prepare_read_request(&ring, cqe->res)) {
                    break;
                }
                break;
            case EVENT_TYPE_READ:
                int response = 0;
                if (cqe->res >= (int)VHOST_USER_HDR_SIZE &&
                    cqe->res <= (int)sizeof(VhostUserMsg))
                {
                    printf("============= Vhost user message =============\n");
                    response = dispatch_client_request(request->msg);
                    printf("==============================================\n");
                } else if (cqe->res == 0) {
                    printf("Connection lost: %d\n", request->client_socket);
                } else {
                    printf("Unexpected request size: %d\n", cqe->res);
                }

                if (!response) {
                    if(close(request->client_socket)) {
                        perror("close() failed");
                    } else {
                        printf(
                            "Connection closed: %d\n",
                            request->client_socket);
                    }
                    free(request->msg);
                } else {
                    if (prepare_write_request(
                        &ring,
                        request->client_socket,
                        request->msg))
                    {
                        break;
                    }
                }

                break;
            case EVENT_TYPE_WRITE:
                printf("Message sent: %d bytes\n", cqe->res);

                if (prepare_read_request(&ring, request->client_socket)) {
                    free(request->msg);
                    free(request);
                    // TODO: free() other requests in queue.
                    io_uring_cqe_seen(&ring, cqe);
                    io_uring_queue_exit(&ring);
                    return -1;
                }
                free(request->msg);

                break;
            default:
                fprintf(
                    stderr,
                    "Unexpected event type: %d\n",
                    request->event_type);
                break;
        }

        free(request);
        io_uring_cqe_seen(&ring, cqe);
    }

    io_uring_queue_exit(&ring);

    return 0;
}


int rawstor_vu_server(
    int object_id,
    const char *socket_path)
{
    (void)(object_id);

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
