#include "create.h"
#include "remove.h"
#include "show.h"
#include "testio.h"
#include "units.h"

#include "config.h"

#include <rawstorstd/gcc.h>

#include <rawstor.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static struct sigaction sact = {};

static void usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor-cli [options] <command> [command_options]\n"
        "\n"
        "options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  --sessions            Number of opened sessions per object\n"
        "  -v, --version         Rawstor client version\n"
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

static void version(void) {
    fprintf(stdout, "Rawstor CLI " PACKAGE_VERSION "\n");
}

static void sact_handler(int RAWSTOR_UNUSED s) {
}

static void command_create_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor-cli [options] create [command_options]\n"
        "\n"
        "command options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  -s, --size SIZE       Object size with unit suffix (B, K, M, G, "
        "T).\n"
        "                        Examples: 10G, 5M, 2T.\n"
        "  -l, --location LOCATION\n"
        "                        Comma separated list of rawstor backend "
        "locations\n"
    );
};

static int command_create(int argc, char** argv) {
    const char* optstring = "hs:l:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"location", required_argument, NULL, 'l'},
        {"size", required_argument, NULL, 's'},
        {},
    };

    char* size_arg = NULL;
    char* location_arg = NULL;
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

        case 'l':
            location_arg = optarg;
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

    if (location_arg == NULL) {
        fprintf(stderr, "location required\n");
        return EXIT_FAILURE;
    }

    size_t size = 0;
    int res = rawstor_cli_size_to_bytes(size_arg, &size);
    if (res < 0) {
        fprintf(
            stderr, "Failed to parse units: %s\nError: %s\n", size_arg,
            strerror(-res)
        );
        return EXIT_FAILURE;
    }

    return rawstor_cli_create(location_arg, size);
}

static void command_remove_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor-cli [options] remove [command_options]\n"
        "\n"
        "command options:\n"
        "  -t, --target TARGET   Comma separated list of rawstor backend "
        "targets\n"
    );
};

static int command_remove(int argc, char** argv) {
    const char* optstring = "ht:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"target", required_argument, NULL, 't'},
        {},
    };

    char* target_arg = NULL;
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

        case 't':
            target_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (target_arg == NULL) {
        fprintf(stderr, "target required\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_remove(target_arg);
}

static void command_show_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor-cli [options] show [command_options]\n"
        "\n"
        "command options:\n"
        "  -t, --target TARGET   Comma separated list of rawstor backend "
        "targets\n"
    );
};

static int command_show(int argc, char** argv) {
    const char* optstring = "ht:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"target", required_argument, NULL, 't'},
        {},
    };

    char* target_arg = NULL;
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

        case 't':
            target_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EXIT_FAILURE;
    }

    if (target_arg == NULL) {
        fprintf(stderr, "target required\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_show(target_arg);
}

static void command_testio_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor-cli [options] testio [command_options]\n"
        "\n"
        "command options:\n"
        "  -b, --block-size BLOCK_SIZE\n"
        "                        Block size with unit suffix (B, K, M, G, T"
        ").\n"
        "  -c, --count COUNT\n   How many blocks are we going to be\n"
        "                        reading/writing in bytes\n"
        "  -d, --io-depth IO_DEPTH\n"
        "                        IO depth\n"
        "  -h, --help            Show this help message and exit\n"
        "  -t, --target TARGET   Comma separated list of rawstor backend "
        "targets\n"
        "  --vector-mode         Use readv/writev\n"
    );
};

static int command_testio(int argc, char** argv) {
    const char* optstring = "b:c:d:ht:";
    struct option longopts[] = {
        {"block-size", required_argument, NULL, 'b'},
        {"count", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"io-depth", required_argument, NULL, 'd'},
        {"target", required_argument, NULL, 't'},
        {"vector-mode", no_argument, NULL, 'v'},
        {},
    };

    char* block_size_arg = NULL;
    char* count_arg = NULL;
    char* io_depth_arg = NULL;
    char* target_arg = NULL;
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

        case 't':
            target_arg = optarg;
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
    int res = rawstor_cli_size_to_bytes(block_size_arg, &block_size);
    if (res < 0) {
        fprintf(
            stderr, "Failed to parse units: %s\nError: %s\n", block_size_arg,
            strerror(-res)
        );
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

    if (target_arg == NULL) {
        fprintf(stderr, "target required\n");
        return EXIT_FAILURE;
    }

    return rawstor_cli_testio(
        target_arg, block_size, count, io_depth, vector_mode
    );
}

static int run_command(
    const char* command, const struct RawstorOpts* opts, int argc, char** argv
) {
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

int main(int argc, char** argv) {
    const char* optstring = "+hv";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"sessions", required_argument, NULL, 's'},
        {"version", no_argument, NULL, 'v'},
        {"wait-timeout", required_argument, NULL, 't'},
        {},
    };

    char* sessions_arg = NULL;
    char* wait_timeout_arg = NULL;
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

        case 'v':
            version();
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

    sact.sa_handler = sact_handler;
    sigemptyset(&sact.sa_mask);
    if (sigaction(SIGINT, &sact, NULL) == -1) {
        int errsv = errno;
        errno = 0;
        fprintf(
            stderr, "Failed to register SIGINT handler: %s\n", strerror(errsv)
        );
        return EXIT_FAILURE;
    }
    if (sigaction(SIGTERM, &sact, NULL) == -1) {
        int errsv = errno;
        errno = 0;
        fprintf(
            stderr, "Failed to register SIGTERM handler: %s\n", strerror(errsv)
        );
        return EXIT_FAILURE;
    }

    int ret = run_command(argv[optind], &opts, argc - optind, &argv[optind]);

    return ret;
}
