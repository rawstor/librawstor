#include "create.h"
#include "testio.h"

#include <rawstor.h>

#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


static void usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli [options] <command> [command_options]\n"
        "\n"
        "options:\n"
        "  -h, --help            Show this help message and exit\n"
        "\n"
        "command:\n"
        "  create                Create rawstor object\n"
        "  testio                Test rawstor IO routines\n"
        "\n"
        "command options:        Run `<command> --help` to show command usage\n"
    );
};


static void command_create_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli create [command_options]\n"
        "\n"
        "command options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  -s, --size SIZE       Object size in Gb\n"
    );
};


static int command_create(int argc, char **argv) {
    const char *optstring = "hs:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"size", required_argument, NULL, 's'},
        {},
    };

    char *size_arg = NULL;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                command_create_usage();
                return EXIT_SUCCESS;
                break;

            case 's':
                size_arg = optarg;
                break;

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }
 
    if (size_arg == NULL) {
        fprintf(stderr, "size required\n");
        return EXIT_FAILURE;
    }

    size_t size = 0;
    if (sscanf(size_arg, "%zu", &size) != 1) {
        fprintf(stderr, "size argument must be unsigned integer\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_create(size);
}


static void command_testio_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli testio [command_options]\n"
        "\n"
        "command options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  -o, --object-id OBJECT_ID\n"
        "                        Rawstor object id\n"
        "  -v, --vector-mode     Use readv/writev\n"
    );
};


static int command_testio(int argc, char **argv) {
    const char *optstring = "ho:v";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-id", required_argument, NULL, 'o'},
        {"vector-mode", required_argument, NULL, 'v'},
        {},
    };

    int vector_mode = 0;
    char *object_id_arg = NULL;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                command_testio_usage();
                return EXIT_SUCCESS;
                break;

            case 'o':
                object_id_arg = optarg;
                break;

            case 'v':
                vector_mode = 1;
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
        fprintf(stderr, "object-id required\n");
        return EXIT_FAILURE;
    }

    int object_id = 0;
    if (sscanf(object_id_arg, "%d", &object_id) != 1) {
        fprintf(stderr, "object-id argument must be integer\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_testio(object_id, vector_mode);
}


int main(int argc, char **argv) {
    const char *optstring = "+h";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {},
    };

    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage();
                return EXIT_SUCCESS;
                break;

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind > argc - 1) {
        usage();
        return EXIT_FAILURE;
    }

    char *command = argv[optind];
    if (strcmp(command, "create") == 0) {
        return command_create(argc - optind, &argv[optind]);
    }

    if (strcmp(command, "testio") == 0) {
        return command_testio(argc - optind, &argv[optind]);
    }

    printf("Unexpected command: %s\n", command);
    return EXIT_FAILURE;
}
