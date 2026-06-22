#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <unistd.h>

#include <algorithm>
#include <exception>
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
    std::vector<char> _buf;
    std::function<void(const void*)> _cb;

public:
    CommandRead(
        const char* name, size_t size, std::function<void(const void*)>&& cb
    ) :
        Command(name),
        _buf(size),
        _cb(std::move(cb)) {}

    CommandType type() const noexcept override { return CT_READ; }
    void* buf() noexcept { return _buf.data(); }
    size_t size() const noexcept { return _buf.size(); }
    void cb() const { _cb(_buf.data()); }
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

Server::Server(int port, unsigned int depth) :
    _fd(-1),
    _in(-1),
    _out(-1),
    _exit(false),
    _client_fd(-1),
    _depth(depth),
    _thread(nullptr) {
    _fd = socket(AF_INET, SOCK_STREAM, 0);
    if (_fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    sockaddr_in addr = {};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    try {
        int fds[2];
        if (pipe(fds) == -1) {
            RAWSTD_THROW_ERRNO();
        };
        _out = fds[0];
        _in = fds[1];

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

        if (_in != -1) {
            ::close(_in);
        }

        if (_out != -1) {
            ::close(_out);
        }

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

    if (_in != -1) {
        ::close(_in);
    }

    if (_out != -1) {
        ::close(_out);
    }

    if (_fd != -1) {
        ::close(_fd);
    }
}

void Server::_main(Server* server) noexcept {
    try {
        server->_loop();
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
    } catch (...) {
        rawstd_error("Unexpected error\n");
    }
}

void Server::_notify() {
    int value = 1;
    int res = ::write(_in, &value, sizeof(value));
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    if (res != sizeof(value)) {
        throw std::runtime_error("Partial write");
    }
}

void Server::_loop() {
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(_depth);

    std::shared_ptr<std::function<void(size_t, int)>> cb =
        std::make_shared<std::function<void(size_t, int)>>();

    auto wrapper = [cb]() {
        return [cb](size_t result, int error) { (*cb)(result, error); };
    };

    unsigned int value;
    *cb = [this, &queue, &value, &wrapper](size_t result, int error) {
        if (error) {
            RAWSTD_THROW_SYSTEM_ERROR(error);
        }
        if (result == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
        }
        if (result != sizeof(value)) {
            throw std::runtime_error("Partial read");
        }

        std::shared_ptr<Command> command;
        {
            std::unique_lock lock(_mutex);
            if (!_commands.empty()) {
                command = _commands.front();
                _commands.pop_front();
            }
        }

        if (command.get() != nullptr) {
            switch (command->type()) {
            case CT_ACCEPT:
                _do_accept(*queue.get(), command);
                break;
            case CT_CLOSE:
                _do_close(*queue.get(), command);
                break;
            case CT_READ:
                _do_read(*queue.get(), command);
                break;
            case CT_STOP:
                _exit = 1;
                return;
            case CT_WRITE:
                _do_write(*queue.get(), command);
                break;
            case CT_WRITEV:
                _do_writev(*queue.get(), command);
                break;
            }
        }

        queue->read(_out, &value, sizeof(value), wrapper());
    };
    queue->read(_out, &value, sizeof(value), wrapper());

    while (!_exit) {
        queue->wait();
    }

    queue.reset();
}

void Server::_do_accept(rawio::Queue& queue, std::shared_ptr<Command> command) {
    auto command_accept = std::dynamic_pointer_cast<CommandAccept>(command);
    queue.accept(
        _fd, nullptr, nullptr,
        [this, command_accept](int result) {
            _notify();

            if (result < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-result);
            }
            RAWSTD_TRACE_EVENT_MESSAGE(
                command_accept->trace_event, "accepted on fd: %zu\n", result
            );
            assert(_client_fd == -1);
            _client_fd = result;
        }
    );
}

void Server::_do_close(rawio::Queue&, std::shared_ptr<Command> command) {
    _notify();

    int res = ::close(_client_fd);
    if (res == -1) {
        RAWSTD_THROW_ERRNO();
    }
    RAWSTD_TRACE_EVENT_MESSAGE(
        command->trace_event, "closed: %d\n", _client_fd
    );
    _client_fd = -1;
}

void Server::_do_read(rawio::Queue& queue, std::shared_ptr<Command> command) {
    assert(_client_fd != -1);

    auto command_read = std::dynamic_pointer_cast<CommandRead>(command);
    queue.read(
        _client_fd, command_read->buf(), command_read->size(),
        [this, command_read](size_t result, int error) {
            _notify();

            RAWSTD_TRACE_EVENT_MESSAGE(
                command_read->trace_event, "read(): result = %zu, error = %d\n",
                result, error
            );
            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }
            if (result == 0) {
                RAWSTD_THROW_SYSTEM_ERROR(EPIPE);
            }
            if (static_cast<size_t>(result) != command_read->size()) {
                throw std::runtime_error("Partial read");
            }
            command_read->cb();
        }
    );
}

void Server::_do_write(rawio::Queue& queue, std::shared_ptr<Command> command) {
    assert(_client_fd != -1);

    auto command_write = std::dynamic_pointer_cast<CommandWrite>(command);
    queue.write(
        _client_fd, command_write->buf(), command_write->size(),
        [this, command_write](size_t result, int error) {
            _notify();

            RAWSTD_TRACE_EVENT_MESSAGE(
                command_write->trace_event,
                "write(): result = %zu, error = %d\n", result, error
            );
            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }
            if (static_cast<size_t>(result) != command_write->size()) {
                throw std::runtime_error("Partial write");
            }
        }
    );
}

void Server::_do_writev(rawio::Queue& queue, std::shared_ptr<Command> command) {
    assert(_client_fd != -1);

    auto command_writev = std::dynamic_pointer_cast<CommandWriteV>(command);
    queue.writev(
        _client_fd, command_writev->iov(), command_writev->niov(),
        [this, command_writev](size_t result, int error) {
            _notify();

            RAWSTD_TRACE_EVENT_MESSAGE(
                command_writev->trace_event, "result = %zu, error = %d\n",
                result, error
            );
            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }
            if (static_cast<size_t>(result) !=
                rawstd_iovec_size(
                    command_writev->iov(), command_writev->niov()
                )) {
                throw std::runtime_error("Partial write");
            }
        }
    );
}

void Server::_stop() {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandStop>());
    if (_commands.size() == 1) {
        _notify();
    }
}

void Server::accept(const char* name) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandAccept>(name));
    if (_commands.size() == 1) {
        _notify();
    }
}

void Server::close(const char* name) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandClose>(name));
    if (_commands.size() == 1) {
        _notify();
    }
}

void Server::read(
    const char* name, size_t size, std::function<void(const void* buf)>&& cb
) {
    std::unique_lock lock(_mutex);
    _commands.push_back(
        std::make_shared<CommandRead>(name, size, std::move(cb))
    );
    if (_commands.size() == 1) {
        _notify();
    }
}

void Server::write(const char* name, const void* buf, size_t size) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandWrite>(name, buf, size));
    if (_commands.size() == 1) {
        _notify();
    }
}

void Server::writev(const char* name, const iovec* iov, unsigned int niov) {
    std::unique_lock lock(_mutex);
    _commands.push_back(std::make_shared<CommandWriteV>(name, iov, niov));
    if (_commands.size() == 1) {
        _notify();
    }
}

} // namespace tests
} // namespace rawstor
