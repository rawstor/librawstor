#include "server.hpp"

#include <rawstor.h>

#include <getopt.h>
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

#include <iostream>


namespace {


struct sigaction sact;


void usage() {
    std::cerr <<
        "Rawstor vhost server" << std::endl
        << std::endl
        << "usage: rawstor-vhost [-h] -o OBJECT_ID -s SOCKET_PATH" << std::endl
        << std::endl
        << "options:" << std::endl
        << "  -h, --help            "
            "Show this help message and exit" << std::endl
        << "  -o, --object-uri OBJECT_URI" << std::endl
        << "                        Comma separated list "
                                    "of Rawstor URI targets." << std::endl
        << "  -s, --socket-path SOCKET_PATH" << std::endl
        << "                        "
            "This option specify the location of the" << std::endl
        << "                        "
            "vhost-user Unix domain socket." << std::endl;
}


void sact_handler(int s) {
    std::cout << "Caught signal:" << s << std::endl;
}


} // namespace


int main(int argc, char **argv) {
    const char *optstring = "ho:s:";
    struct option longopts[] = {
        {"help", no_argument, NULL, 'h'},
        {"object-uri", required_argument, NULL, 'o'},
        {"socket-path", required_argument, NULL, 's'},
        {},
    };

    const char *object_uri_arg = NULL;
    const char *socket_path_arg = NULL;
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
                object_uri_arg = optarg;
                break;

            case 's':
                socket_path_arg = optarg;
                break;

            default:
                return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
    }

    if (object_uri_arg == NULL) {
        std::cerr << "object-uri argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (socket_path_arg == NULL) {
        std::cerr << "socket-path argument required" << std::endl;
        return EXIT_FAILURE;
    }

    sact.sa_handler = sact_handler;
    sigemptyset(&sact.sa_mask);
    sigaction(SIGINT, &sact, NULL);

    try {
        rawstor::vhost::server(object_uri_arg, socket_path_arg);
    } catch (std::exception &e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
