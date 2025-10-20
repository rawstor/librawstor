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
        "usage: rawstor-cli [options] <command> [command_options]\n"
        "\n"
        "options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  --sessions            Number of opened sessions per object\n"
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
        "  -u, --uri RAWSTOR_URI Comma separated list of Rawstor URI targets\n"
    );
};


static int command_create(int argc, char **argv) {
    const char *optstring = "hs:u:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"size", required_argument, NULL, 's'},
        {"uri", required_argument, NULL, 'u'},
        {},
    };

    char *size_arg = NULL;
    char *uri_arg = NULL;
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

    if (size_arg == NULL) {
        fprintf(stderr, "size required\n");
        return EXIT_FAILURE;
    }

    if (uri_arg == NULL) {
        fprintf(stderr, "uri required\n");
        return EXIT_FAILURE;
    }

    size_t size = 0;
    if (sscanf(size_arg, "%zu", &size) != 1) {
        fprintf(stderr, "size argument must be unsigned integer\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_create(uri_arg, size);
}


static void command_remove_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli [options] remove [command_options]\n"
        "\n"
        "command options:\n"
        "  -o, --object-uri OBJECT_URI\n"
        "                        Comma separated list of Rawstor URI targets\n"
    );
};


static int command_remove(int argc, char **argv) {
    const char *optstring = "ho:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-uri", required_argument, NULL, 'o'},
        {},
    };

    char *object_uri_arg = NULL;
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
                object_uri_arg = optarg;
                break;

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (object_uri_arg == NULL) {
        fprintf(stderr, "object-uri required\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_remove(object_uri_arg);
}


static void command_show_usage() {
    fprintf(
        stderr,
        "Rawstor CLI\n"
        "\n"
        "usage: rawstor-cli [options] show [command_options]\n"
        "\n"
        "command options:\n"
        "  -o, --object-uri OBJECT_URI\n"
        "                        Comma separated list of Rawstor URI targets\n"
    );
};


static int command_show(int argc, char **argv) {
    const char *optstring = "ho:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-uri", required_argument, NULL, 'o'},
        {},
    };

    char *object_uri_arg = NULL;
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
                object_uri_arg = optarg;
                break;

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (object_uri_arg == NULL) {
        fprintf(stderr, "object-uri required\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_show(object_uri_arg);
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
        "  -o, --object-uri OBJECT_URI\n"
        "                        Comma separated list of Rawstor URI targets\n"
        "  --vector-mode         Use readv/writev\n"
    );
};


static int command_testio(int argc, char **argv) {
    const char *optstring = "b:c:d:ho:s:";
    struct option longopts[] = {
        {"block-size", required_argument, NULL, 'b'},
        {"count", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"io-depth", required_argument, NULL, 'd'},
        {"object-uri", required_argument, NULL, 'o'},
        {"vector-mode", required_argument, NULL, 'v'},
        {},
    };

    char *block_size_arg = NULL;
    char *count_arg = NULL;
    char *io_depth_arg = NULL;
    char *object_uri_arg = NULL;
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
                object_uri_arg = optarg;
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

    if (object_uri_arg == NULL) {
        fprintf(stderr, "object-uri required\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_testio(
        object_uri_arg,
        block_size, count, io_depth,
        vector_mode);
}


static int run_command(
    const char *command,
    const struct RawstorOpts *opts,
    int argc, char **argv)
{
    int res = rawstor_initialize(opts);
    if (res) {
        fprintf(stderr, "rawstor_initialize() failed: %s\n", strerror(-res));
        return EXIT_FAILURE;
    }

    int ret;
    if (strcmp(command, "create") == 0) {
        ret = command_create(argc, argv);
    } else if (strcmp(command, "remove") == 0) {
        ret = command_remove(argc, argv);
    } else if (strcmp(command, "show") == 0) {
        ret = command_show(argc, argv);
    } else if (strcmp(command, "testio") == 0) {
        ret = command_testio(argc, argv);
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
        {"sessions", required_argument, NULL, 's'},
        {"wait-timeout", required_argument, NULL, 't'},
        {},
    };

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

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind > argc - 1) {
        usage();
        return EXIT_FAILURE;
    }

    struct RawstorOpts opts = {};

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
        argv[optind], &opts, argc - optind, &argv[optind]);

    return ret;
}
