#include "server.hpp"

#include "protocol.h"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include <memory>
#include <sstream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>


/* The version of the protocol we support */
#define VHOST_USER_VERSION 1


namespace {


int get_features(VhostUserMsg *msg) {
    msg->payload.u64 =
        /*
         * The following VIRTIO feature bits are supported by our virtqueue
         * implementation:
         */
        1ULL << VIRTIO_F_NOTIFY_ON_EMPTY |
        1ULL << VIRTIO_RING_F_INDIRECT_DESC |
        1ULL << VIRTIO_RING_F_EVENT_IDX |
        1ULL << VIRTIO_F_VERSION_1 |

        /* vhost-user feature bits */
        1ULL << VHOST_F_LOG_ALL |
        1ULL << VHOST_USER_F_PROTOCOL_FEATURES;

    msg->size = sizeof(msg->payload.u64);
    msg->fd_num = 0;

    printf(
        "Sending back to guest u64: 0x%llx\n",
        (unsigned long long)msg->payload.u64);

    return 1;
}


int get_protocol_features(VhostUserMsg *msg) {
    /*
     * Note that we support, but intentionally do not set,
     * VHOST_USER_PROTOCOL_F_INBAND_NOTIFICATIONS. This means that
     * a device implementation can return it in its callback
     * (get_protocol_features) if it wants to use this for
     * simulation, but it is otherwise not desirable (if even
     * implemented by the frontend.)
     */
    msg->payload.u64 = 1ULL << VHOST_USER_PROTOCOL_F_MQ |
                       1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD |
                       1ULL << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
                       1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER |
                       1ULL << VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD |
                       1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK |
                       1ULL << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
                       1ULL << VHOST_USER_PROTOCOL_F_CONFIG;

    msg->payload.u64 &= ~(1ULL << VHOST_USER_PROTOCOL_F_INFLIGHT_SHMFD);

    msg->size = sizeof(msg->payload.u64);
    msg->fd_num = 0;

    printf(
        "Sending back to guest u64: 0x%llx\n",
        (unsigned long long)msg->payload.u64);

    return 1;
}


int dispatch_vhost_request(VhostUserMsg *msg) {
    printf("Request: %d\n", msg->request);
    printf("Flags:   0x%x\n", msg->flags);
    printf("Size:    %u\n", msg->size);

    switch (msg->request) {
        case VHOST_USER_GET_FEATURES:
            return get_features(msg);
        case VHOST_USER_GET_PROTOCOL_FEATURES:
            return get_protocol_features(msg);
        default:
            printf("Unexpected request: %d\n", msg->request);
    };
    return 0;
}


int server_read(size_t result, int error, void *data);


int server_write(size_t result, int error, void *data);


int server_read(size_t result, int error, void *data) {
    // TODO: implement server in CPP.
    int client_socket = 0; // rawstor_io_event_fd(event);
    VhostUserMsg *msg = (VhostUserMsg*)data;

    if (error != 0) {
        fprintf(stderr, "read() failed: %s\n", strerror(error));
        return -error;
    }

    if (result == 0) {
        fprintf(
            stderr,
            "Connection lost: %d\n", client_socket);
        return 0;
    } else if (
        result < (int)VHOST_USER_HDR_SIZE ||
        result > (int)sizeof(VhostUserMsg)
    ) {
        fprintf(
            stderr,
            "Unexpected request size: %zu\n", result);
        return -EPROTO;
    }

    int response = 0;

    printf("============= Vhost user message =============\n");
    response = dispatch_vhost_request(msg);
    printf("==============================================\n");

    if (!response &&
        msg->flags & VHOST_USER_NEED_REPLY_MASK)
    {
        msg->payload.u64 = 0;
        msg->size = sizeof(msg->payload.u64);
        msg->fd_num = 0;
        response = 1;
    }

    if (!response) {
        return 0;
    }

    msg->flags = VHOST_USER_VERSION |
                 VHOST_USER_REPLY_MASK;

    int res = rawstor_fd_write(
        client_socket, msg, VHOST_USER_HDR_SIZE + msg->size,
        server_write, msg);
    if (res)
    {
        fprintf(stderr, "rawstor_fd_write() failed: %s\n", strerror(-res));
        return res;
    }

    return 0;
}


int server_write(size_t result, int error, void *data) {
    // TODO: implement server in CPP.
    int client_socket = 0; // rawstor_io_event_fd(event);
    VhostUserMsg *msg = (VhostUserMsg*)data;

    if (error != 0) {
        fprintf(stderr, "write() failed: %s\n", strerror(error));
        return -error;
    }

    printf("Message sent: %ld bytes\n", result);

    int res = rawstor_fd_read(
        client_socket, msg, sizeof(*msg),
        server_read, msg);
    if (res) {
        fprintf(stderr, "rawstor_fd_read() failed: %s\n", strerror(-res));
        return res;
    }

    return 0;
}


int open_unix_socket(const std::string &socket_path) {
    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket < 0) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        struct sockaddr_un addr;
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, socket_path.c_str(), sizeof(addr.sun_path) - 1);

        if (bind(server_socket, (struct sockaddr *)&addr, sizeof(addr))) {
            RAWSTOR_THROW_ERRNO();
        }

        try {
            if (listen(server_socket, 1)) {
                RAWSTOR_THROW_ERRNO();
            }
        } catch (...) {
            unlink(socket_path.c_str());
            throw;
        }

        return server_socket;
    } catch (...) {
        close(server_socket);
        throw;
    }
}


void close_unix_socket(const std::string &socket_path, int fd) {
    if (unlink(socket_path.c_str())) {
        RAWSTOR_THROW_ERRNO();
    }

    if (close(fd)) {
        RAWSTOR_THROW_ERRNO();
    }
}


class Client final {
    private:
        int _fd;

    public:
        explicit Client(int fd):
            _fd(fd)
        {}
        Client(const Client &) = delete;
        Client(Client &&) = delete;
        ~Client() {
            try {
                if (close(_fd)) {
                    RAWSTOR_THROW_ERRNO();
                }
            } catch (std::exception &e) {
                std::ostringstream oss;
                oss << "Failed to close socket: " << e.what();
                rawstor_error("%s\n", oss.str().c_str());
            }
        }

        Client& operator=(const Client &) = delete;
        Client& operator=(Client &&) = delete;

        void loop() {
            VhostUserMsg msg;

            int res = rawstor_fd_read(
                _fd, &msg, sizeof(VhostUserMsg),
                server_read, &msg);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }

            while (!rawstor_empty()) {
                res = rawstor_wait();
                if (res) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
            }
        }
};


class Server final {
    private:
        std::string _socket_path;
        int _fd;

    public:
        explicit Server(const std::string &socket_path):
            _socket_path(socket_path),
            _fd(open_unix_socket(_socket_path))
        {}
        Server(const Server &) = delete;
        Server(Server &&) = delete;
        ~Server() {
            try {
                close_unix_socket(_socket_path, _fd);
            } catch (std::exception &e) {
                std::ostringstream oss;
                oss << "Failed to close socket " << _socket_path << ": "
                    << e.what();
                rawstor_error("%s\n", oss.str().c_str());
            }
        }

        std::unique_ptr<Client> accept() {
            int s = ::accept(_fd, NULL, NULL);
            if (s < 0) {
                RAWSTOR_THROW_ERRNO();
            }
            return std::make_unique<Client>(s);
        }

        Server& operator=(const Server &) = delete;
        Server& operator=(Server &&) = delete;
};


} // unnamed

namespace rawstor {
namespace vhost {


void server(const std::string &, const std::string &socket_path) {
    int res = rawstor_initialize(NULL);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    };

    rawstor_info("Listening %s\n", socket_path.c_str());

    try {
        Server s(socket_path);

        std::unique_ptr<Client> c = s.accept();

        c->loop();

        rawstor_terminate();
    } catch (...) {
        rawstor_terminate();
    }
}


}} // rawstor::vhost
