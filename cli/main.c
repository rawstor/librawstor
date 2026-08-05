#include "create.h"
#include "info.h"
#include "list.h"
#include "remove.h"
#include "show.h"
#include "testio.h"
#include "units.h"

#include "config.h"

#include <rawstd/exitcode.h>
#include <rawstd/gcc.h>

#include <rawstor.h>

#include <errno.h>
#include <getopt.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sysexits.h>

#define DEFAULT_QUEUE_SIZE 256

static struct sigaction sact = {};

static void usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor [options] <command> [command_options]\n"
        "\n"
        "options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  --sessions            Number of opened sessions per object\n"
        "  -v, --version         Rawstor version\n"
        "\n"
        "command:\n"
        "  list                  List rawstor objects\n"
        "  create                Create rawstor object\n"
        "  remove                Remove rawstor object\n"
        "  show                  Show rawstor object\n"
        "  info                  Show rawstor location info\n"
        "  testio                Test rawstor IO routines\n"
        "\n"
        "command options:        Run `<command> --help` to show command usage\n"
    );
};

static void version(void) {
    fprintf(stdout, "Rawstor CLI " PACKAGE_VERSION "\n");
}

static void sact_handler(int RAWSTD_UNUSED s) {
}

static void command_create_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor [options] create LOCATION [-u UUID] "
        "[command_options]\n"
        "       rawstor [options] create -t TARGET [command_options]\n"
        "\n"
        "create by location (backend list, optional UUID):\n"
        "  LOCATION              Comma-separated list of rawstor backend "
        "locations.\n"
        "                        If -u is omitted, a random UUIDv7 is "
        "generated.\n"
        "  -u, --uuid UUID       Explicit UUID for the object (only valid "
        "when creating by location).\n"
        "\n"
        "create by target (pre-formatted targets with embedded UUID):\n"
        "  -t, --target TARGET   Comma-separated list of rawstor backend "
        "targets.\n"
        "                        Each target must include the UUID, e.g. "
        "ost://host/uuid.\n"
        "\n"
        "command options:\n"
        "  -h, --help            Show this help message and exit\n"
        "  -s, --size SIZE       Object size with unit suffix (B, K, M, G, "
        "T, P, E).\n"
        "                        Examples: 10G, 5M, 2T.\n"
    );
};

static int command_create(int argc, char** argv) {
    const char* optstring = "hs:t:u:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"size", required_argument, NULL, 's'},
        {"target", required_argument, NULL, 't'},
        {"uuid", required_argument, NULL, 'u'},
        {},
    };

    const char* location_arg = NULL;
    const char* size_arg = NULL;
    const char* target_arg = NULL;
    const char* uuid_arg = NULL;
    optind = 0;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            command_create_usage();
            return EXIT_SUCCESS;

        case 's':
            size_arg = optarg;
            break;

        case 't':
            target_arg = optarg;
            break;

        case 'u':
            uuid_arg = optarg;
            break;

        default:
            return EX_USAGE;
        }
    }

    if (target_arg == NULL && optind < argc) {
        location_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }

    if (size_arg == NULL) {
        fprintf(stderr, "size required\n");
        return EX_USAGE;
    }

    if (location_arg != NULL && target_arg != NULL) {
        fprintf(stderr, "location and target are mutually exclusive\n");
        return EX_USAGE;
    }

    if (target_arg != NULL && uuid_arg != NULL) {
        fprintf(stderr, "Unexpected argument: uuid\n");
        return EX_USAGE;
    }

    if (uuid_arg != NULL && location_arg == NULL) {
        fprintf(stderr, "uuid argument requires location\n");
        return EX_USAGE;
    }

    if (location_arg == NULL && target_arg == NULL) {
        fprintf(stderr, "location or target required\n");
        return EX_USAGE;
    }

    uint64_t size = 0;
    int res = rawstor_cli_size_to_bytes(size_arg, &size);
    if (res < 0) {
        fprintf(
            stderr, "Failed to parse units: %s\nError: %s\n", size_arg,
            strerror(-res)
        );
        return EX_USAGE;
    }

    if (target_arg != NULL) {
        return rawstor_cli_create(target_arg, size);
    } else {
        return rawstor_cli_create_at(location_arg, uuid_arg, size);
    }
}

static void command_remove_usage(void) {
    fprintf(
        stdout, "Rawstor CLI " PACKAGE_VERSION "\n"
                "\n"
                "usage: rawstor [options] remove TARGET [command_options]\n"
                "\n"
                "command options:\n"
                "  -h, --help            Show this help message and exit\n"
    );
};

static int command_remove(int argc, char** argv) {
    const char* optstring = "h";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {},
    };

    char* target_arg = NULL;
    optind = 0;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            command_remove_usage();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        target_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }

    if (target_arg == NULL) {
        fprintf(stderr, "target required\n");
        return EX_USAGE;
    }

    return rawstor_cli_remove(target_arg);
}

static void command_list_usage(void) {
    fprintf(
        stdout, "Rawstor CLI " PACKAGE_VERSION "\n"
                "\n"
                "usage: rawstor [options] list LOCATION [command_options]\n"
                "\n"
                "command options:\n"
                "  -h, --help            Show this help message and exit\n"
    );
}

static int command_list(int argc, char** argv) {
    const char* optstring = "h";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {},
    };

    char* location_arg = NULL;
    optind = 0;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            command_list_usage();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        location_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }

    if (location_arg == NULL) {
        fprintf(stderr, "location required\n");
        return EX_USAGE;
    }

    return rawstor_cli_list(location_arg);
}

static void command_info_usage(void) {
    fprintf(
        stdout, "Rawstor CLI " PACKAGE_VERSION "\n"
                "\n"
                "usage: rawstor [options] info LOCATION [command_options]\n"
                "\n"
                "command options:\n"
                "  -h, --help            Show this help message and exit\n"
    );
}

static int command_info(int argc, char** argv) {
    const char* optstring = "h";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {},
    };

    char* location_arg = NULL;
    optind = 0;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            command_info_usage();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        location_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }

    if (location_arg == NULL) {
        fprintf(stderr, "location required\n");
        return EX_USAGE;
    }

    return rawstor_cli_info(location_arg);
}

static void command_show_usage(void) {
    fprintf(
        stdout, "Rawstor CLI " PACKAGE_VERSION "\n"
                "\n"
                "usage: rawstor [options] show TARGET [command_options]\n"
                "\n"
                "command options:\n"
                "  -h, --help            Show this help message and exit\n"
    );
};

static int command_show(int argc, char** argv) {
    const char* optstring = "h";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {},
    };

    char* target_arg = NULL;
    optind = 0;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            command_show_usage();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        target_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }

    if (target_arg == NULL) {
        fprintf(stderr, "target required\n");
        return EX_USAGE;
    }

    return rawstor_cli_show(target_arg);
}

static void command_testio_usage(void) {
    fprintf(
        stdout,
        "Rawstor CLI " PACKAGE_VERSION "\n"
        "\n"
        "usage: rawstor [options] testio TARGET [command_options]\n"
        "\n"
        "command options:\n"
        "  --queue-size SIZE     RawIO queue size (default: %u)\n"
        "  -b, --block-size SIZE Block size with unit suffix (B, K, M, G, T, "
        "P, E).\n"
        "  -c, --count COUNT     How many blocks are we going to be\n"
        "                        reading/writing in bytes\n"
        "  -d, --io-depth DEPTH  IO depth\n"
        "  -h, --help            Show this help message and exit\n"
        "  --vector-mode         Use readv/writev\n",
        DEFAULT_QUEUE_SIZE
    );
};

static int command_testio(int argc, char** argv) {
    const char* optstring = "b:c:d:h";
    struct option longopts[] = {
        {"queue-size", required_argument, NULL, 'q'},
        {"block-size", required_argument, NULL, 'b'},
        {"count", required_argument, NULL, 'c'},
        {"help", no_argument, NULL, 'h'},
        {"io-depth", required_argument, NULL, 'd'},
        {"vector-mode", no_argument, NULL, 'v'},
        {},
    };

    char* queue_size_arg = NULL;
    char* block_size_arg = NULL;
    char* count_arg = NULL;
    char* io_depth_arg = NULL;
    char* target_arg = NULL;
    int vector_mode = 0;
    optind = 0;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'q':
            queue_size_arg = optarg;
            break;

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

        case 'v':
            vector_mode = 1;
            break;

        default:
            return EX_USAGE;
        }
    }

    if (optind < argc) {
        target_arg = argv[optind];
        optind++;
    }

    if (optind < argc) {
        fprintf(stderr, "Unexpected argument: %s\n", argv[optind]);
        return EX_USAGE;
    }

    unsigned int queue_size = DEFAULT_QUEUE_SIZE;
    if (queue_size_arg != NULL) {
        if (sscanf(queue_size_arg, "%u", &queue_size) != 1) {
            fprintf(stderr, "queue-size argument must be unsigned integer\n");
            return EX_USAGE;
        }
    }

    if (block_size_arg == NULL) {
        fprintf(stderr, "block-size required\n");
        return EX_USAGE;
    }

    uint64_t block_size = 0;
    int res = rawstor_cli_size_to_bytes(block_size_arg, &block_size);
    if (res < 0) {
        fprintf(
            stderr, "Failed to parse units: %s\nError: %s\n", block_size_arg,
            strerror(-res)
        );
        return EX_USAGE;
    }

    if (count_arg == NULL) {
        fprintf(stderr, "count required\n");
        return EX_USAGE;
    }

    unsigned int count = 0;
    if (sscanf(count_arg, "%u", &count) != 1) {
        fprintf(stderr, "count argument must be unsigned integer\n");
        return EX_USAGE;
    }

    if (io_depth_arg == NULL) {
        fprintf(stderr, "io-depth required\n");
        return EX_USAGE;
    }

    unsigned int io_depth = 0;
    if (sscanf(io_depth_arg, "%u", &io_depth) != 1) {
        fprintf(stderr, "io-depth argument must be unsigned integer\n");
        return EX_USAGE;
    }

    if (target_arg == NULL) {
        fprintf(stderr, "target required\n");
        return EX_USAGE;
    }

    return rawstor_cli_testio(
        queue_size, target_arg, block_size, count, io_depth, vector_mode
    );
}

static int run_command(
    const char* command, const struct RawstorOpts* opts, int argc, char** argv
) {
    int res = rawstor_initialize(opts);
    if (res) {
        fprintf(stderr, "rawstor_initialize() failed: %s\n", strerror(-res));
        return rawstd_exitcode_for_errno(-res);
    }

    int ret;
    if (strcmp(command, "create") == 0) {
        ret = command_create(argc, argv);
    } else if (strcmp(command, "remove") == 0) {
        ret = command_remove(argc, argv);
    } else if (strcmp(command, "list") == 0) {
        ret = command_list(argc, argv);
    } else if (strcmp(command, "show") == 0) {
        ret = command_show(argc, argv);
    } else if (strcmp(command, "info") == 0) {
        ret = command_info(argc, argv);
    } else if (strcmp(command, "testio") == 0) {
        ret = command_testio(argc, argv);
    } else {
        printf("Unexpected command: %s\n", command);
        ret = EX_USAGE;
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
        {},
    };

    char* sessions_arg = NULL;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
        case 'h':
            usage();
            return EXIT_SUCCESS;

        case 's':
            sessions_arg = optarg;
            break;

        case 'v':
            version();
            return EXIT_SUCCESS;

        default:
            return EX_USAGE;
        }
    }

    if (optind > argc - 1) {
        usage();
        return EX_USAGE;
    }

    struct RawstorOpts opts = {};

    if (sessions_arg != NULL) {
        if (sscanf(sessions_arg, "%u", &opts.sessions) != 1) {
            fprintf(stderr, "sessions argument must be unsigned integer\n");
            return EX_USAGE;
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
        return rawstd_exitcode_for_errno(errsv);
    }
    if (sigaction(SIGTERM, &sact, NULL) == -1) {
        int errsv = errno;
        errno = 0;
        fprintf(
            stderr, "Failed to register SIGTERM handler: %s\n", strerror(errsv)
        );
        return rawstd_exitcode_for_errno(errsv);
    }

    int ret = run_command(argv[optind], &opts, argc - optind, &argv[optind]);

    return ret;
}
