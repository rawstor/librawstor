#include <mds/server.hpp>

#include <mds/client.hpp>

#include <rawstd/coro.hpp>
#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>

#include <arpa/inet.h>

#include <sys/socket.h>

#include <unistd.h>

#include <exception>
#include <sstream>
#include <string>
#include <system_error>

#include <cerrno>
#include <cstring>

namespace {

int accept_trampoline(ssize_t result, void* data) {
    auto* stream = static_cast<rawstd::CallbackStream<int>*>(data);
    if (result < 0) {
        stream->complete(0, static_cast<int>(-result));
    } else {
        stream->complete(static_cast<int>(result), 0);
    }
    return 0;
}

int wake_read_trampoline(ssize_t result, void* data) {
    static_cast<rawstd::CallbackAwaitable<void>*>(data)->complete(result);
    return 0;
}

} // namespace

namespace rawstor {
namespace mdsserver {

Server::Server(
    unsigned int queue_size, int listen_fd, ObjectStore& store, int wake_fd
) :
    _queue(nullptr),
    _fd(listen_fd),
    _wake_fd(wake_fd),
    _stop(false),
    _store(store),
    _accept_event(nullptr) {
    int res = rawio_queue_create(queue_size, &_queue);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

Server::~Server() {
    _clients.clear();

    if (_accept_event != nullptr) {
        int res = rawio_cancel(_queue, _accept_event);
        if (res < 0) {
            rawstd_warning("Failed to cancel event: %s\n", strerror(-res));
        }
    }

    rawio_queue_delete(_queue);
}

int Server::bind_listen(const std::string& addr, unsigned int port) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        int res = rawstd_socket_set_reuse(fd);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        sockaddr_in sin = {};
        sin.sin_family = AF_INET;
        res = inet_pton(AF_INET, addr.c_str(), &sin.sin_addr);
        if (res == 0) {
            std::ostringstream oss;
            oss << "the address was not parseable: " << addr;
            throw std::runtime_error(oss.str());
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }
        sin.sin_port = htons(port);

        if (bind(fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (listen(fd, SOMAXCONN) == -1) {
            RAWSTD_THROW_ERRNO();
        }
    } catch (...) {
        close(fd);
        throw;
    }

    return fd;
}

rawstd::Task<void> Server::_add_client(int fd) {
    std::exception_ptr error;
    std::shared_ptr<Client> client;
    try {
        client = co_await Client::create(_queue, *this, fd);
    } catch (...) {
        error = std::current_exception();
    }

    if (error) {
        ::close(fd);
        std::rethrow_exception(error);
    }

    rawstd_info("MDS client connected: fd=%d\n", fd);
    _clients.emplace(fd, std::move(client));
}

rawstd::Task<void> Server::del_client(int fd) {
    auto it = _clients.find(fd);
    if (it != _clients.end()) {
        _clients.erase(it);
        rawstd_info("MDS client disconnected: fd=%d\n", fd);
    }
    co_return;
}

rawstd::DetachedTask Server::_accept_task() {
    // io_uring can end a multishot accept on its own (e.g. on a full
    // completion ring), which the stream reports as ENOBUFS: the
    // registration is then armed again rather than leaving the server
    // deaf to new connections.
    while (true) {
        rawstd::CallbackStream<int> stream;
        int res = rawio_accept_multishot(
            _queue, _fd, accept_trampoline, &stream, &_accept_event
        );
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        int error = 0;
        while (error == 0) {
            int fd;
            try {
                fd = co_await stream.next();
            } catch (const std::system_error& e) {
                error = e.code().value();
                // ECANCELED is ~Server()'s own rawio_cancel() -- an
                // ordinary, silent shutdown, not a failure worth logging.
                if (error == ENOBUFS) {
                    rawstd_warning("%s; re-arming accept\n", e.what());
                } else if (error != ECANCELED) {
                    rawstd_error("%s\n", e.what());
                }
                break;
            }

            try {
                co_await _add_client(fd);
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }

        if (error != ENOBUFS) {
            co_return;
        }
    }
}

rawstd::DetachedTask Server::_wake_task() {
    char buf[1];
    rawstd::CallbackAwaitable<void> awaiter;
    int res = rawio_read(
        _queue, _wake_fd, buf, sizeof(buf), wake_read_trampoline, &awaiter
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    co_await awaiter;
    _stop = true;
}

void Server::loop() {
    _accept_task();
    if (_wake_fd != -1) {
        _wake_task();
    }
    rawstd::DetachedTask::rethrow_if_pending();

    while (!_stop) {
        int res = rawio_wait(_queue);
        if (res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

} // namespace mdsserver
} // namespace rawstor
