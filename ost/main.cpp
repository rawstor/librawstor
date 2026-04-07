#include <getopt.h>

#include <iostream>
#include <sstream>

#include <cstdio>
#include <cstdlib>

namespace {

void usage() {
    std::cerr << "Rawstor OST server with a file-based backend." << std::endl
              << std::endl
              << "usage: rawstor-file-ost [-h] -d DATA_DIR -a ADDR" << std::endl
              << std::endl
              << "options:" << std::endl
              << "  -h, --help            "
                 "Show this help message and exit."
              << std::endl
              << "  -d, --data-dir DATA_DIR" << std::endl
              << "                        Path to the directory where object "
              << "data will be stored." << std::endl
              << "  -a, --addr ADDR       Bind address in the format "
              << "<ip>:<port> (e.g., 127.0.0.1:8080)." << std::endl;
}

void ost(
    const std::string& addr, unsigned int port, const std::string& data_dir
) {
    std::cout << "addr = " << addr << std::endl
              << "port = " << port << std::endl
              << "data_dir = " << data_dir << std::endl;
}

void parse_addr(
    const std::string& addr, std::string* name, unsigned int* port
) {
    size_t colon_delim = addr.find(":");
    if (colon_delim != addr.npos) {
        *name = addr.substr(0, colon_delim);
        colon_delim += 1;
        std::istringstream iss(addr.substr(colon_delim));
        iss >> *port;
    } else {
        *name = addr;
        *port = 0;
    }
}

} // namespace

int main(int argc, char** argv) {
    const char* optstring = "hd:a:";
    struct option longopts[] = {
        {"help", no_argument, nullptr, 'h'},
        {"data-dir", required_argument, nullptr, 'd'},
        {"addr", required_argument, nullptr, 'a'},
        {},
    };

    const char* data_dir_arg = nullptr;
    const char* addr_arg = nullptr;
    while (1) {
        int c = getopt_long(argc, argv, optstring, longopts, nullptr);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();
            return EXIT_SUCCESS;
            break;

        case 'd':
            data_dir_arg = optarg;
            break;

        case 'a':
            addr_arg = optarg;
            break;

        default:
            return EXIT_FAILURE;
        }
    }

    if (optind < argc) {
        std::cerr << "Unexpected argument: " << argv[optind] << std::endl;
        return EXIT_FAILURE;
    }

    if (data_dir_arg == nullptr) {
        std::cerr << "data-dir argument required" << std::endl;
        return EXIT_FAILURE;
    }

    if (addr_arg == nullptr) {
        std::cerr << "addr argument required" << std::endl;
        return EXIT_FAILURE;
    }

    try {
        std::string name;
        unsigned int port;
        parse_addr(addr_arg, &name, &port);
        ost(name, port, data_dir_arg);
    } catch (const std::exception& e) {
        std::cerr << e.what() << std::endl;
        return EXIT_FAILURE;
    }

    return EXIT_SUCCESS;
}
