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
    optreset = 1;
    optind = 1;
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
        "  -b, --block-size BLOCK_SIZE\n"
        "                        Block size in bytes\n"
        "  -c, --count COUNT\n   How many blocks are we going to be\n"
        "                        reading/writing in bytes\n"
        "  -d, --io-depth IO_DEPTH\n"
        "                        IO depth\n"
        "  -h, --help            Show this help message and exit\n"
        "  -o, --object-id OBJECT_ID\n"
        "                        Rawstor object id\n"
        "  --vector-mode         Use readv/writev\n"
    );
};


static int command_testio(int argc, char **argv) {
    const char *optstring = "b:d:ho:s:v";
    struct option longopts[] = {
        {"block-size", required_argument, NULL, 'b'},
        {"count", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"io-depth", required_argument, NULL, 'd'},
        {"object-id", required_argument, NULL, 'o'},
        {"vector-mode", required_argument, NULL, 'v'},
        {},
    };

    char *block_size_arg = NULL;
    char *count_arg = NULL;
    char *io_depth_arg = NULL;
    char *object_id_arg = NULL;
    int vector_mode = 0;
    optreset = 1;
    optind = 1;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'b':
                block_size_arg = optarg;
                break;

            case 'c':
                count_arg = optarg;
                break;

            case 'd':
                io_depth_arg = optarg;
                break;

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
 
    if (block_size_arg == NULL) {
        fprintf(stderr, "block-size required\n");
        return EXIT_FAILURE;
    }

    size_t block_size = 0;
    if (sscanf(block_size_arg, "%zu", &block_size) != 1) {
        fprintf(stderr, "block-size argument must be unsigned integer\n");
        return EXIT_FAILURE;
    }

    if (count_arg == NULL) {
        fprintf(stderr, "count required\n");
        return EXIT_FAILURE;
    }

    unsigned int count = 0;
    if (sscanf(count_arg, "%u", &count) != 1) {
        fprintf(stderr, "count argument must be unsigned integer\n");
        return EXIT_FAILURE;
    }

    if (io_depth_arg == NULL) {
        fprintf(stderr, "io-depth required\n");
        return EXIT_FAILURE;
    }

    unsigned int io_depth = 0;
    if (sscanf(io_depth_arg, "%u", &io_depth) != 1) {
        fprintf(stderr, "io-depth argument must be unsigned integer\n");
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

    return rawstor_cli_testio(
        object_id,
        block_size, count, io_depth,
        vector_mode);
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
