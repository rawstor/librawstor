#include "server.hpp"

#include "device.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <rawstor/rawstor.h>

#include <inttypes.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <sstream>
#include <string>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

// A previous instance killed outright (SIGKILL, a crash) never got to
// unlink its socket, so bind(2) would fail with EADDRINUSE and every
// restart with it. Remove the socket file if nothing is listening on it
// any more -- connecting is the only way to tell; a live instance still
// makes bind(2) fail as before.
void remove_stale_socket(const sockaddr_un& addr) {
    struct stat st;
    if (lstat(addr.sun_path, &st) || !S_ISSOCK(st.st_mode)) {
        errno = 0;
        return;
    }

    int probe = socket(AF_UNIX, SOCK_STREAM, 0);
    if (probe < 0) {
        RAWSTD_THROW_ERRNO();
    }
    int res =
        connect(probe, reinterpret_cast<const sockaddr*>(&addr), sizeof(addr));
    int errsv = errno;
    close(probe);
    if (res && errsv == ECONNREFUSED) {
        rawstd_info("Removing stale socket %s\n", addr.sun_path);
        if (unlink(addr.sun_path) && errno != ENOENT) {
            RAWSTD_THROW_ERRNO();
        }
    }
    errno = 0;
}

int open_unix_socket(const std::string& socket_path) {
    int server_socket = socket(AF_UNIX, SOCK_STREAM, 0);
    if (server_socket < 0) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        // So this listen socket doesn't leak into a child forked by the
        // LVM/ZFS storage backends to shell out to lvcreate/zfs/etc.
        // (src/subprocess.cpp).
        int res = rawstd_socket_set_cloexec(server_socket);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        sockaddr_un addr = {};
        addr.sun_family = AF_UNIX;

        res = snprintf(
            addr.sun_path, sizeof(addr.sun_path), "%s", socket_path.c_str()
        );
        if (res < 0) {
            RAWSTD_THROW_ERRNO();
        }
        if ((size_t)res >= sizeof(addr.sun_path)) {
            std::ostringstream oss;
            oss << "Socket path is greater than " << sizeof(addr.sun_path) - 1
                << " characters";
            throw std::runtime_error(oss.str());
        }

        remove_stale_socket(addr);

        if (bind(
                server_socket, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)
            )) {
            RAWSTD_THROW_ERRNO();
        }

        try {
            // bind(2) leaves the socket's mode at 0777 masked by whatever
            // umask the caller happened to have -- pin it down explicitly
            // instead of relying on that. connect(2) to a UNIX stream
            // socket requires *write* permission on the socket file itself
            // (see unix(7)), so group-readable-only (e.g. mode 0755 under
            // the common umask 0022) would silently prevent anyone but the
            // owner from connecting; 0660 grants owner and group, nobody
            // else. Note: fchmod(2) on the socket fd does *not* affect the
            // bound pathname's permissions on Linux -- this must be a
            // path-based chmod(2).
            if (chmod(socket_path.c_str(), 0660)) {
                RAWSTD_THROW_ERRNO();
            }

            if (listen(server_socket, 1)) {
                RAWSTD_THROW_ERRNO();
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

void close_unix_socket(const std::string& socket_path, int fd) {
    if (unlink(socket_path.c_str())) {
        RAWSTD_THROW_ERRNO();
    }

    if (close(fd)) {
        RAWSTD_THROW_ERRNO();
    }
}

} // namespace

namespace rawstor {
namespace vhost {

Server::Server(
    unsigned int queue_size, const std::string& target,
    const std::string& socket_path, bool write_cache_enabled, bool readonly,
    int wake_fd
) :
    _queue_size(queue_size),
    _target(target),
    _socket_path(socket_path),
    _write_cache_enabled(write_cache_enabled),
    _readonly(readonly),
    _fd(open_unix_socket(_socket_path)),
    _wake_fd(wake_fd) {
}

Server::~Server() {
    try {
        close_unix_socket(_socket_path, _fd);
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Failed to close socket " << _socket_path << ": " << e.what();
        rawstd_error("%s\n", oss.str().c_str());
    }
}

void Server::loop() {
    rawstd_info("Listening %s\n", _socket_path.c_str());

    int fd = ::accept(_fd, NULL, NULL);
    if (fd < 0) {
        if (errno == EINTR) {
            errno = 0;
            return;
        }
        RAWSTD_THROW_ERRNO();
    }

    // So this connection's fd doesn't leak into a child forked by the
    // LVM/ZFS storage backends to shell out to lvcreate/zfs/etc.
    // (src/subprocess.cpp).
    int res = rawstd_socket_set_cloexec(fd);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    res = rawstd_socket_set_nosigpipe(fd);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    rawstd_info("Client connected: fd=%d\n", fd);

    Device device(
        _queue_size, _target, fd, _write_cache_enabled, _readonly, _wake_fd
    );
    device.loop();
}

} // namespace vhost
} // namespace rawstor
