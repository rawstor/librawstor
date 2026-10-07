#include "server.hpp"

#include "device.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>
#include <rawstd/socket.h>

#include <rawstor/rawstor.h>

#include <fcntl.h>
#include <inttypes.h>
#include <sys/file.h>
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

// Take `<socket_path>.lock`, failing with EADDRINUSE if another
// rawstor-vhost already holds it -- i.e. is serving (or still setting up,
// or tearing down) that socket. The lock file is never unlinked: removing
// it would let two instances each lock a different inode under the same
// name.
int lock_socket_path(const std::string& socket_path) {
    std::string lock_path = socket_path + ".lock";
    int fd = open(lock_path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0660);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (flock(fd, LOCK_EX | LOCK_NB)) {
        int errsv = errno;
        close(fd);
        if (errsv == EWOULDBLOCK) {
            rawstd_error(
                "Another rawstor-vhost already serves %s\n", socket_path.c_str()
            );
            RAWSTD_THROW_SYSTEM_ERROR(EADDRINUSE);
        }
        RAWSTD_THROW_SYSTEM_ERROR(errsv);
    }
    return fd;
}

// A previous instance killed outright (SIGKILL, a crash) never got to
// unlink its socket, so bind(2) would fail with EADDRINUSE and every
// restart with it. Called with the path's lock held (lock_socket_path()),
// so no other rawstor-vhost can be binding it concurrently; the connect
// probe only guards against some unrelated process listening there,
// which still makes bind(2) fail as before.
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
    _lock_fd(lock_socket_path(_socket_path)),
    _fd(-1),
    _wake_fd(wake_fd) {
    try {
        _fd = open_unix_socket(_socket_path);
    } catch (...) {
        close(_lock_fd);
        throw;
    }
}

Server::~Server() {
    try {
        close_unix_socket(_socket_path, _fd);
    } catch (const std::exception& e) {
        std::ostringstream oss;
        oss << "Failed to close socket " << _socket_path << ": " << e.what();
        rawstd_error("%s\n", oss.str().c_str());
    }

    // Only once the socket is gone, so the next instance can't find it
    // half torn down.
    close(_lock_fd);
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
