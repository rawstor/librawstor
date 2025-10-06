#include "create.h"
#include "remove.h"
#include "show.h"
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
        "usage: rawstor-cli <--uri URI> [options] <command> [command_options]\n"
        "\n"
        "options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  --sessions            Number of opened sessions per object\n"
        "  --uri                 Rawstor URI\n"
        "  --wait-timeout        IO wait timeout\n"
        "\n"
        "command:\n"
        "  create                Create rawstor object\n"
        "  remove                Remove rawstor object\n"
        "  show                  Show rawstor object\n"
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
        "usage: rawstor-cli [options] create [command_options]\n"
        "\n"
        "command options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  -s, --size SIZE       Object size in Gb\n"
    );
};


static int command_create(const char *uri, int argc, char **argv) {
    const char *optstring = "hs:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"size", required_argument, NULL, 's'},
        {},
    };

    char *size_arg = NULL;
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

    return rawstor_cli_create(uri, size);
}


static void command_remove_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli [options] remove [command_options]\n"
        "\n"
        "command options:\n"
        "  -o, --object-id OBJECT_ID\n"
        "                        Rawstor object id\n"
    );
};


static int command_remove(const char *uri, int argc, char **argv) {
    const char *optstring = "ho:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-id", required_argument, NULL, 'o'},
        {},
    };

    char *object_id_arg = NULL;
    optind = 1;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                command_remove_usage();
                return EXIT_SUCCESS;
                break;

            case 'o':
                object_id_arg = optarg;
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

    struct RawstorUUID object_id;
    if (rawstor_uuid_from_string(&object_id, object_id_arg)) {
        fprintf(stderr, "object-id argument must be valid UUID\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_remove(uri, &object_id);
}


static void command_show_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli [options] show [command_options]\n"
        "\n"
        "command options:\n"
        "  -o, --object-id OBJECT_ID\n"
        "                        Rawstor object id\n"
    );
};


static int command_show(const char *uri, int argc, char **argv) {
    const char *optstring = "ho:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-id", required_argument, NULL, 'o'},
        {},
    };

    char *object_id_arg = NULL;
    optind = 1;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
            case 'h':
                command_show_usage();
                return EXIT_SUCCESS;
                break;

            case 'o':
                object_id_arg = optarg;
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

    struct RawstorUUID object_id;
    if (rawstor_uuid_from_string(&object_id, object_id_arg)) {
        fprintf(stderr, "object-id argument must be valid UUID\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_show(uri, &object_id);
}


static void command_testio_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli [options] testio [command_options]\n"
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


static int command_testio(const char *uri, int argc, char **argv) {
    const char *optstring = "b:c:d:ho:s:";
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

    struct RawstorUUID object_id;
    if (rawstor_uuid_from_string(&object_id, object_id_arg)) {
        fprintf(stderr, "object-id argument must be valid UUID\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_testio(
        uri,
        &object_id,
        block_size, count, io_depth,
        vector_mode);
}


static int run_command(
    const char *command,
    const struct RawstorOpts *opts,
    const char *uri,
    int argc, char **argv)
{
    int res = rawstor_initialize(opts);
    if (res) {
        fprintf(stderr, "rawstor_initialize() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    int ret;
    if (strcmp(command, "create") == 0) {
        ret = command_create(uri, argc, argv);
    } else if (strcmp(command, "remove") == 0) {
        ret = command_remove(uri, argc, argv);
    } else if (strcmp(command, "show") == 0) {
        ret = command_show(uri, argc, argv);
    } else if (strcmp(command, "testio") == 0) {
        ret = command_testio(uri, argc, argv);
    } else {
        printf("Unexpected command: %s\n", command);
        ret = EXIT_FAILURE;
    }

    rawstor_terminate();

    return ret;
}


int main(int argc, char **argv) {
    const char *optstring = "+h";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"uri", required_argument, NULL, 'u'},
        {"sessions", required_argument, NULL, 's'},
        {"wait-timeout", required_argument, NULL, 't'},
        {},
    };

    char *uri_arg = NULL;
    char *sessions_arg = NULL;
    char *wait_timeout_arg = NULL;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
            case 'h':
                usage();
                return EXIT_SUCCESS;
                break;

            case 's':
                sessions_arg = optarg;
                break;

            case 't':
                wait_timeout_arg = optarg;
                break;

            case 'u':
                uri_arg = optarg;
                break;

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind > argc - 1) {
        usage();
        return EXIT_FAILURE;
    }

    struct RawstorOpts opts = {};

    if (uri_arg == NULL) {
        fprintf(stderr, "uri argument required\n");
        return EXIT_FAILURE;
    }

    if (sessions_arg != NULL) {
        if (sscanf(sessions_arg, "%u", &opts.sessions) != 1) {
            fprintf(stderr, "sessions argument must be unsigned integer\n");
            return EXIT_FAILURE;
        }
    }

    if (wait_timeout_arg != NULL) {
        if (sscanf(wait_timeout_arg, "%u", &opts.wait_timeout) != 1) {
            fprintf(stderr, "wait-timeout argument must be unsigned integer\n");
            return EXIT_FAILURE;
        }
    }

    int ret = run_command(
        argv[optind], &opts, uri_arg, argc - optind, &argv[optind]);

    return ret;
}
