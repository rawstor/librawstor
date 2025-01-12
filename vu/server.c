#include "server.h"

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

#define EVENT_TYPE_ACCEPT 0


typedef struct {
    int event_type;
    int session;
} Request;


static int add_accept_request(struct io_uring *ring, int s) {
    Request *req = malloc(sizeof(Request));
    if (req == NULL) {
        perror("malloc() failed:");
        return -1;
    }
    req->event_type = EVENT_TYPE_ACCEPT;

    struct io_uring_sqe *sqe = io_uring_get_sqe(ring);
    io_uring_prep_accept(sqe, s, NULL, NULL, 0);

    io_uring_sqe_set_data(sqe, req);
    io_uring_submit(ring);
    return 0;
}


static int server_loop(int s) {
    int rval;
    struct io_uring ring;

    rval = io_uring_queue_init(QUEUE_DEPTH, &ring, 0);
    if (rval) {
        fprintf(
            stderr,
            "io_uring_queue_init() failed: %s\n",
            strerror(-rval));
        return -1;
    };

    if (add_accept_request(&ring, s)) {
        io_uring_queue_exit(&ring);
        return -1;
    }

    struct io_uring_cqe *cqe;
    while (1) {
        printf("Waiting for event...\n");
        rval = io_uring_wait_cqe(&ring, &cqe);
        if (rval) {
            fprintf(
                stderr,
                "io_uring_wait_cqe() failed: %s\n",
                strerror(-rval));
            if (rval == -EINTR) {
                break;
            }
            // TODO: Fatal error here?
            continue;
        }

        Request *req = (Request*)cqe->user_data;
        printf("Event received: %d\n", req->event_type);
        if (cqe->res < 0) {
            fprintf(
                stderr,
                "io_uring request failed for event %d: %s\n",
                req->event_type,
                strerror(-cqe->res));
            free(req);
            io_uring_cqe_seen(&ring, cqe);
            // TODO: Fatal error here?
            continue;
        }

        switch (req->event_type) {
            case EVENT_TYPE_ACCEPT:
                if(close(cqe->res)) {
                    perror("close() failed");
                }
                free(req);
                if (add_accept_request(&ring, s)) {
                    // TODO: free() other requests in queue.
                    io_uring_cqe_seen(&ring, cqe);
                    io_uring_queue_exit(&ring);
                    return -1;
                }
                break;
            default:
                fprintf(
                    stderr,
                    "Unexpected event type: %d\n",
                    req->event_type);
                free(req);
                break;
        }

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

    int s = socket(AF_UNIX, SOCK_STREAM, 0);
    if (s < 0) {
        perror("socket() failed");
        return -1;
    }

    struct sockaddr_un addr = {
        .sun_family = AF_UNIX
    };
    strncpy(addr.sun_path, socket_path, sizeof(addr.sun_path) - 1);

    if (bind(s, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind() failed");
        if (close(s)) {
            err(EXIT_FAILURE, NULL);
        }
        return -1;
    }

    if (listen(s, 1)) {
        perror("listen() failed");
        if (unlink(addr.sun_path)) {
            err(EXIT_FAILURE, NULL);
        }
        if (close(s)) {
            err(EXIT_FAILURE, NULL);
        }
        return -1;
    }

    int rval = server_loop(s);

    if (unlink(socket_path)) {
        perror("unlink() failed");
        if (close(s)) {
            err(EXIT_FAILURE, NULL);
        }
        return -1;
    }

    if (close(s)) {
        perror("close() failed");
        return -1;
    }

    return rval;
}
