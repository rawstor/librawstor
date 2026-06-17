#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <unistd.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <mutex>
#include <new>
#include <string>
#include <thread>
#include <vector>

#include <cassert>
#include <cstdio>
#include <ctime>

namespace rawstor {
namespace tests {

enum CommandType {
    CT_ACCEPT,
    CT_CLOSE,
    CT_READ,
    CT_STOP,
    CT_WRITE,
    CT_WRITEV,
};

class Command {
public:
    rawstd::TraceEvent trace_event;

    explicit Command(const char* name) :
        trace_event(RAWSTD_TRACE_EVENT('!', "%s\n", name)) {}
    virtual ~Command() = default;
    Command(const Command&) = delete;
    Command(Command&&) = delete;

    Command& operator=(const Command&) = delete;
    Command& operator=(Command&&) = delete;

    virtual CommandType type() const noexcept = 0;
};

class CommandAccept final : public Command {
public:
    CommandAccept(const char* name) : Command(name) {}

    CommandType type() const noexcept override { return CT_ACCEPT; }
};

class CommandClose final : public Command {
public:
    CommandClose(const char* name) : Command(name) {}

    CommandType type() const noexcept override { return CT_CLOSE; }
};

class CommandRead final : public Command {
private:
    size_t _size;
    std::function<void(const void*, size_t)> _cb;

public:
    CommandRead(
        const char* name, size_t size,
        std::function<void(const void*, size_t)>&& cb
    ) :
        Command(name),
        _size(size),
        _cb(std::move(cb)) {}

    CommandType type() const noexcept override { return CT_READ; }
    size_t size() const noexcept { return _size; }
    void callback(const void* buf, size_t result) const { _cb(buf, result); }
};

class CommandStop final : public Command {
public:
    CommandStop() : Command("") {}
    CommandType type() const noexcept override { return CT_STOP; }
};

class CommandWrite final : public Command {
private:
    std::vector<char> _buf;

public:
    CommandWrite(const char* name, const void* buf, size_t size) :
        Command(name),
        _buf(
            static_cast<const char*>(buf), static_cast<const char*>(buf) + size
        ) {}

    CommandType type() const noexcept override { return CT_WRITE; }
    const void* buf() noexcept { return _buf.data(); }
    size_t size() const noexcept { return _buf.size(); }
};

class CommandWriteV final : public Command {
private:
    std::vector<std::vector<char>> _data;
    std::vector<iovec> _iov;

public:
    CommandWriteV(const char* name, const iovec* iov, unsigned int niov) :
        Command(name) {
        _data.reserve(niov);
        _iov.reserve(niov);
        for (unsigned int i = 0; i < niov; ++i) {
            _data.emplace_back(
                static_cast<const char*>(iov[i].iov_base),
                static_cast<const char*>(iov[i].iov_base) + iov[i].iov_len
            );
            _iov.push_back({
                .iov_base = _data[i].data(),
                .iov_len = _data[i].size(),
            });
        }
    }

    CommandType type() const noexcept override { return CT_WRITEV; }
    const iovec* iov() const noexcept { return _iov.data(); }
    unsigned int niov() const noexcept { return _iov.size(); }
};

Server::Server(int port) : _fd(-1), _client_fd(-1), _thread(nullptr) {
    _fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    try {
        int value = 1;
        if (setsockopt(_fd, SOL_SOCKET, SO_REUSEADDR, &value, sizeof(value)) ==
            -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (bind(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (listen(_fd, 1)) {
            RAWSTD_THROW_ERRNO();
        }
        _thread = std::make_unique<std::thread>(Server::_main, this);
    } catch (...) {
        ::close(_fd);
        throw;
    }
}

Server::~Server() {
    if (_thread != nullptr) {
        _stop();
        _thread->join();
    }

    if (_client_fd != -1) {
        ::close(_client_fd);
    }

    if (_fd != -1) {
        ::close(_fd);
    }
}

void Server::_main(Server* server) {
    server->_loop();
}

void Server::_loop() {
    bool exit = false;
    while (!exit) {
        std::unique_lock lock(_mutex);
        if (_commands.empty()) {
            _push_condition.wait(lock);
        }
        assert(!_commands.empty());
        std::shared_ptr<Command> command = _commands.front();
        _commands.pop_front();
        switch (command->type()) {
        case CT_ACCEPT:
            _do_accept(*command.get());
            break;
        case CT_CLOSE:
            _do_close(*command.get());
            break;
        case CT_READ:
            _do_read(*command.get());
            break;
        case CT_STOP:
            exit = true;
            break;
        case CT_WRITE:
            _do_write(*command.get());
            break;
        case CT_WRITEV:
            _do_writev(*command.get());
            break;
        }
        _pop_condition.notify_one();
    }
}

void Server::_do_accept(Command& command) {
    assert(_client_fd == -1);

    RAWSTD_TRACE_EVENT_MESSAGE(command.trace_event, "%s()\n", "accept");
    int fd = ::accept(_fd, NULL, NULL);
    RAWSTD_TRACE_EVENT_MESSAGE(
        command.trace_event, "%s(): fd = %d\n", "accept", fd
    );
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    _client_fd = fd;
}

void Server::_do_close(Command& command) {
    RAWSTD_TRACE_EVENT_MESSAGE(command.trace_event, "%s()\n", "close");
    int res = ::close(_client_fd);
    RAWSTD_TRACE_EVENT_MESSAGE(
        command.trace_event, "%s(): res = %d\n", "close", res
    );
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    _client_fd = -1;
}

void Server::_do_read(Command& command) {
    assert(_client_fd != -1);

    CommandRead& command_read = dynamic_cast<CommandRead&>(command);
    RAWSTD_TRACE_EVENT_MESSAGE(command_read.trace_event, "%s()\n", "read");
    std::vector<char> buf(command_read.size());
    ssize_t res = ::read(_client_fd, buf.data(), buf.size());
    RAWSTD_TRACE_EVENT_MESSAGE(
        command_read.trace_event, "%s(): res = %zd\n", "read", res
    );
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    command_read.callback(buf.data(), res);
}

void Server::_do_write(Command& command) {
    assert(_client_fd != -1);

    CommandWrite& command_write = dynamic_cast<CommandWrite&>(command);
    RAWSTD_TRACE_EVENT_MESSAGE(command_write.trace_event, "%s()\n", "write");
    ssize_t res =
        ::write(_client_fd, command_write.buf(), command_write.size());
    RAWSTD_TRACE_EVENT_MESSAGE(
        command_write.trace_event, "%s(): res = %zd\n", "write", res
    );
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (static_cast<size_t>(res) != command_write.size()) {
        throw std::runtime_error("Partial write");
    }
}

void Server::_do_writev(Command& command) {
    assert(_client_fd != -1);

    CommandWriteV& command_writev = dynamic_cast<CommandWriteV&>(command);
    RAWSTD_TRACE_EVENT_MESSAGE(command_writev.trace_event, "%s()\n", "writev");
    ssize_t res =
        ::writev(_client_fd, command_writev.iov(), command_writev.niov());
    RAWSTD_TRACE_EVENT_MESSAGE(
        command_writev.trace_event, "%s(): res = %zd\n", "writev", res
    );
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (static_cast<size_t>(res) !=
        rawstd_iovec_size(command_writev.iov(), command_writev.niov())) {
        throw std::runtime_error("Partial write");
    }
}

void Server::_stop() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandStop>());
    _push_condition.notify_one();
}

void Server::accept(const char* name) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandAccept>(name));
    _push_condition.notify_one();
}

void Server::close(const char* name) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandClose>(name));
    _push_condition.notify_one();
}

void Server::read(
    const char* name, size_t size,
    std::function<void(const void* buf, size_t result)>&& cb
) {
    std::unique_lock lock(_mutex);
    _commands.push_back(
        std::make_shared<CommandRead>(name, size, std::move(cb))
    );
    _push_condition.notify_one();
}

void Server::write(const char* name, const void* buf, size_t size) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandWrite>(name, buf, size));
    _push_condition.notify_one();
}

void Server::writev(const char* name, const iovec* iov, unsigned int niov) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandWriteV>(name, iov, niov));
    _push_condition.notify_one();
}

void Server::wait() {
    std::unique_lock lock(_mutex);
    _pop_condition.wait(lock, [this] { return _commands.empty(); });
}

} // namespace tests
} // namespace rawstor
