#include "server.hpp"

#include <rawstorstd/gpp.hpp>

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
};

class Command {
public:
    virtual ~Command() {}
    virtual CommandType type() const noexcept = 0;
};

class CommandAccept final : public Command {
public:
    CommandAccept() {}
    ~CommandAccept() override {}

    CommandType type() const noexcept override { return CT_ACCEPT; }
};

class CommandClose final : public Command {
public:
    ~CommandClose() override {}

    CommandType type() const noexcept override { return CT_CLOSE; }
};

class CommandRead final : public Command {
private:
    void* _buf;
    size_t _size;

public:
    CommandRead(void* buf, size_t size) : _buf(buf), _size(size) {}
    ~CommandRead() override {}

    CommandType type() const noexcept override { return CT_READ; }
    void* buf() noexcept { return _buf; }
    size_t size() const noexcept { return _size; }
};

class CommandStop final : public Command {
public:
    ~CommandStop() override {}

    CommandType type() const noexcept override { return CT_STOP; }
};

class CommandWrite final : public Command {
private:
    const void* _buf;
    size_t _size;

public:
    CommandWrite(const void* buf, size_t size) : _buf(buf), _size(size) {}
    ~CommandWrite() override {}

    CommandType type() const noexcept override { return CT_WRITE; }
    const void* buf() noexcept { return _buf; }
    size_t size() const noexcept { return _size; }
};

Server::Server(int port) : _fd(-1), _client_fd(-1), _thread(nullptr) {
    _fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr = {.s_addr = htonl(INADDR_ANY)}
    };

    try {
        if (bind(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        if (listen(_fd, 1)) {
            RAWSTOR_THROW_ERRNO();
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
        }
        _pop_condition.notify_one();
    }
}

void Server::_do_accept(Command&) {
    assert(_client_fd == -1);

    int fd = ::accept(_fd, NULL, NULL);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    _client_fd = fd;
}

void Server::_do_close(Command&) {
    int res = ::close(_client_fd);
    if (res == -1) {
        RAWSTOR_THROW_ERRNO();
    }
    _client_fd = -1;
}

void Server::_do_read(Command& command) {
    CommandRead& command_read = dynamic_cast<CommandRead&>(command);
    ssize_t res = ::read(_client_fd, command_read.buf(), command_read.size());
    if (res == -1) {
        RAWSTOR_THROW_ERRNO();
    }
}

void Server::_do_write(Command& command) {
    CommandWrite& command_write = dynamic_cast<CommandWrite&>(command);
    ssize_t res =
        ::write(_client_fd, command_write.buf(), command_write.size());
    if (res == -1) {
        RAWSTOR_THROW_ERRNO();
    }
}

void Server::_stop() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandStop>());
    _push_condition.notify_one();
}

void Server::accept() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandAccept>());
    _push_condition.notify_one();
}

void Server::close() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandClose>());
    _push_condition.notify_one();
}

void Server::read(void* buf, size_t size) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandRead>(buf, size));
    _push_condition.notify_one();
}

void Server::write(const void* buf, size_t size) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandWrite>(buf, size));
    _push_condition.notify_one();
}

void Server::wait() {
    std::unique_lock lock(_mutex);
    _pop_condition.wait(lock, [this] { return _commands.empty(); });
}

} // namespace tests
} // namespace rawstor
