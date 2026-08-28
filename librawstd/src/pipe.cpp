#include "rawstd/pipe.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/socket.h>

#include <unistd.h>

#include <utility>

namespace {

void close_if_owned(int fd) noexcept {
    if (fd != -1) {
        close(fd);
    }
}

} // namespace

namespace rawstd {

Pipe::Pipe() : _read_fd(-1), _write_fd(-1) {
    int fds[2];
    if (pipe(fds) == -1) {
        RAWSTD_THROW_ERRNO();
    }
    _read_fd = fds[0];
    _write_fd = fds[1];

    try {
        int res = rawstd_socket_set_nonblock(_read_fd);
        if (!res) {
            res = rawstd_socket_set_nonblock(_write_fd);
        }
        if (res) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    } catch (...) {
        close_if_owned(_read_fd);
        close_if_owned(_write_fd);
        throw;
    }
}

Pipe::Pipe(Pipe&& other) noexcept :
    _read_fd(std::exchange(other._read_fd, -1)),
    _write_fd(std::exchange(other._write_fd, -1)) {
}

Pipe::~Pipe() {
    close_if_owned(_read_fd);
    close_if_owned(_write_fd);
}

Pipe& Pipe::operator=(Pipe&& other) noexcept {
    if (this != &other) {
        close_if_owned(_read_fd);
        close_if_owned(_write_fd);
        _read_fd = std::exchange(other._read_fd, -1);
        _write_fd = std::exchange(other._write_fd, -1);
    }
    return *this;
}

int Pipe::release_read() noexcept {
    return std::exchange(_read_fd, -1);
}

int Pipe::release_write() noexcept {
    return std::exchange(_write_fd, -1);
}

} // namespace rawstd
