#include "server.h"

#include <err.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>


static void session_loop(int session) {
    printf("Session %d started\n", session);

    // Do the job here

    printf("Session %d finished\n", session);
}


static int server_loop(int s) {
    while (1) {
        printf("Waiting for connection...\n");
        int session = accept(s, NULL, NULL);
        if (session < 0) {
            if (errno == EINTR) {
                printf("Interrupted\n");
                break;
            }
            perror("socket() failed");
            continue;
        }

        session_loop(session);

        if (close(session)) {
            perror("close() failed");
        }
    }

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
