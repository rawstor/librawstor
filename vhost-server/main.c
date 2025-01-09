#include "server.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void usage() {
    fprintf(
        stderr,
        "usage: rawstor-vhost-server [-h] -o OBJECT_ID -s SOCKET_PATH\n"
        "\n"
        "options:\n"
        "  -h, --help            show this help message and exit\n"
        "  -o, --object-id OBJECT_ID\n"
        "                        Rawstor object id.\n"
        "  -s, --socket-path SOCKET_PATH\n"
        "                        This option specify the location of the \n"
        "                        vhost-user Unix domain socket.\n"
    );
}


void sact_handler(int s) {
    printf("Caught signal: %d\n", s);
}


static struct sigaction sact = {
    .sa_handler = sact_handler
};


int main(int argc, const char **argv) {
    int help = 0;
    const char *object_id_arg = NULL;
    const char *socket_path_arg = NULL;

    for (int i = 1; i < argc; ++i) {
        // --help
        if (
            !help && (
                strcmp(argv[i], "-h") == 0 ||
                strcmp(argv[i], "--help") == 0
            )
        ) {
            help = 1;
            continue;
        }

        // --object-id
        if (
            object_id_arg == NULL && (
                strcmp(argv[i], "-o") == 0 ||
                strcmp(argv[i], "--object-id") == 0
            ) &&
            i < argc - 1
        ) {
            object_id_arg = argv[++i];
            continue;
        }

        // --socket-path
        if (
            socket_path_arg == NULL && (
                strcmp(argv[i], "-s") == 0 ||
                strcmp(argv[i], "--socket-path") == 0
            ) &&
            i < argc - 1
        ) {
            socket_path_arg = argv[++i];
            continue;
        }

        fprintf(stderr, "Unexpected argument: %s\n", argv[i]);
        return EXIT_FAILURE;
    }

    if (help) {
        usage();
        return EXIT_SUCCESS;
    }

    if (object_id_arg == NULL) {
        fprintf(stderr, "--object-id argument required\n");
        return EXIT_FAILURE;
    }

    int object_id;
    if (sscanf(object_id_arg, "%d", &object_id) != 1) {
        fprintf(stderr, "--object-id argument must be integer\n");
        return EXIT_FAILURE;
    }

    if (socket_path_arg == NULL) {
        fprintf(stderr, "--socket-path argument required\n");
        return EXIT_FAILURE;
    }

    sigemptyset(&sact.sa_mask);
    sigaction(SIGINT, &sact, NULL);

    rawstor_server(object_id, socket_path_arg);

    return EXIT_SUCCESS;
}
