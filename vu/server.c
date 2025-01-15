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

#define READ_SZ 8192


typedef enum {
    EVENT_TYPE_ACCEPT,
    EVENT_TYPE_READ,
} EventType;


typedef struct {
    EventType event_type;
    int client_socket;
    void *data;
} Request;


static int prepare_accept_request(struct io_uring *ring, int server_socket) {
    Request *request = malloc(sizeof(Request));
    if (request == NULL) {
        perror("malloc() failed:");
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
        perror("malloc() failed:");
        return -1;
    }
    request->data = malloc(READ_SZ);
    memset(request->data, 0, READ_SZ);
    request->event_type = EVENT_TYPE_READ;
    request->client_socket = client_socket;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_read(sqe, client_socket, request->data, READ_SZ, 0);
    io_uring_sqe_set_data(sqe, request);
    return 0;
}


static int dispatch_client_request(const void *data, size_t size) {
    (void)(data);
    printf("received: %ld\n", size);
    printf("msg size: %ld\n", sizeof(VhostUserHeader));
    const VhostUserHeader *header = (const VhostUserHeader *)data;
    printf("request: %d\n", header->request);
    if (header->flags & VHOST_USER_VERSION_MASK) {
        printf("flag: VHOST_USER_VERSION_MASK\n");
    }
    if (header->flags & VHOST_USER_REPLY_MASK) {
        printf("flag: VHOST_USER_REPLY_MASK\n");
    }
    if (header->flags & VHOST_USER_NEED_REPLY_MASK) {
        printf("flag: VHOST_USER_NEED_REPLY_MASK\n");
    }
    printf("size: %d\n", header->size);
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
                if (cqe->res != 0) {
                    dispatch_client_request(request, cqe->res);
                } else {
                    printf("Connection lost: %d\n", request->client_socket);
                }

                if(close(request->client_socket)) {
                    perror("close() failed");
                }
                printf("Connection closed: %d\n", request->client_socket);

                if (prepare_accept_request(&ring, server_socket)) {
                    free(request);
                    // TODO: free() other requests in queue.
                    io_uring_cqe_seen(&ring, cqe);
                    io_uring_queue_exit(&ring);
                    return -1;
                }
                free(request->data);
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
