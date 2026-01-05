#include "server.hpp"

#include <rawstorstd/gpp.hpp>

#include <sys/socket.h>
#include <sys/un.h>

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
namespace io {
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
    char* _data;
    size_t _size;

public:
    CommandRead(size_t size) : _data(nullptr), _size(size) {
        _data = static_cast<char*>(malloc(_size));
        if (_data == nullptr) {
            throw std::bad_alloc();
        }
    }
    ~CommandRead() override { free(_data); }

    CommandType type() const noexcept override { return CT_READ; }
    char* data() noexcept { return _data; }
    size_t size() const noexcept { return _size; }
};

class CommandStop final : public Command {
public:
    ~CommandStop() override {}

    CommandType type() const noexcept override { return CT_STOP; }
};

class CommandWrite final : public Command {
private:
    void* _data;
    size_t _size;

public:
    CommandWrite(const void* data, size_t size) : _data(nullptr), _size(size) {
        _data = malloc(_size);
        if (_data == nullptr) {
            throw std::bad_alloc();
        }
        memcpy(_data, data, _size);
    }
    ~CommandWrite() override { free(_data); }

    CommandType type() const noexcept override { return CT_WRITE; }
    void* data() noexcept { return _data; }
    size_t size() const noexcept { return _size; }
};

Server::Server() : _name(nullptr), _fd(-1), _client_fd(-1), _thread(nullptr) {
    {
        std::string tpl = "/tmp/rawstor_io_tests_server.sock.XXXXXX";
        _name = new char[tpl.length() + 1];
        strncpy(_name, tpl.c_str(), tpl.length() + 1);
    }

    if (mkstemp(_name) == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    unlink(_name);

    _fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (_fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    sockaddr_un addr = {};
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, _name, strlen(_name) + 1);

    try {
        if (bind(_fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        if (listen(_fd, 1)) {
            RAWSTOR_THROW_ERRNO();
        }
    } catch (...) {
        ::close(_fd);
        unlink(_name);
        throw;
    }

    _thread = std::make_unique<std::thread>(Server::_main, this);

    _accept();
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

    if (_name != nullptr) {
        unlink(_name);
        delete[] _name;
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
    ssize_t res = ::read(_client_fd, command_read.data(), command_read.size());
    if (res == -1) {
        RAWSTOR_THROW_ERRNO();
    }
    _buf.clear();
    if (res > 0) {
        _buf.reserve(res);
        std::copy(
            command_read.data(), command_read.data() + res,
            std::back_inserter(_buf)
        );
    }
}

void Server::_do_write(Command& command) {
    CommandWrite& command_write = dynamic_cast<CommandWrite&>(command);
    ssize_t res =
        ::write(_client_fd, command_write.data(), command_write.size());
    if (res == -1) {
        RAWSTOR_THROW_ERRNO();
    }
}

void Server::_accept() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandAccept>());
    _push_condition.notify_one();
}

void Server::_stop() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandStop>());
    _push_condition.notify_one();
}

void Server::close() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandClose>());
    _push_condition.notify_one();
}

void Server::read(size_t size) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandRead>(size));
    _push_condition.notify_one();
}

void Server::write(const void* data, size_t size) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandWrite>(data, size));
    _push_condition.notify_one();
}

void Server::wait() {
    while (true) {
        std::unique_lock lock(_mutex);
        if (!_commands.empty()) {
            _pop_condition.wait(lock);
        }
        if (_commands.empty()) {
            break;
        }
    }
}

const char* Server::buf() const noexcept {
    return _buf.data();
}

size_t Server::buf_size() const noexcept {
    return _buf.size();
}

} // namespace tests
} // namespace io
} // namespace rawstor
