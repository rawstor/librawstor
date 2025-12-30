#include "server.h"

#include <rawstor.h>

#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void usage() {
    fprintf(
        stderr,
        "Rawstor vhost-user server\n"
        "\n"
        "usage: rawstor-vu [-h] -o OBJECT_ID -s SOCKET_PATH\n"
        "\n"
        "options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  -u, --uri URI\n"
        "                        Rawstor URI.\n"
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

static struct sigaction sact = {.sa_handler = sact_handler};

int main(int argc, char** argv) {
    const char* optstring = "ho:s:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-id", required_argument, NULL, 'o'},
        {"socket-path", required_argument, NULL, 's'},
        {"uri", required_argument, NULL, 'u'},
        {},
    };

    const char* object_id_arg = NULL;
    const char* socket_path_arg = NULL;
    const char* uri_arg = NULL;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();
            return EXIT_SUCCESS;
            break;

        case 'o':
            object_id_arg = optarg;
            break;

        case 's':
            socket_path_arg = optarg;
            break;

        case 'u':
            uri_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (object_id_arg == NULL) {
        fprintf(stderr, "object-id argument required\n");
        return EXIT_FAILURE;
    }

    int object_id;
    if (sscanf(object_id_arg, "%d", &object_id) != 1) {
        fprintf(stderr, "object-id argument must be integer\n");
        return EXIT_FAILURE;
    }

    if (socket_path_arg == NULL) {
        fprintf(stderr, "socket-path argument required\n");
        return EXIT_FAILURE;
    }

    if (uri_arg == NULL) {
        fprintf(stderr, "uri argument required\n");
        return EXIT_FAILURE;
    }

    sigemptyset(&sact.sa_mask);
    sigaction(SIGINT, &sact, NULL);

    rawstor_vu_server(uri_arg, object_id, socket_path_arg);

    return EXIT_SUCCESS;
}
