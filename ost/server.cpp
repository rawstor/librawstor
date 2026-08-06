#include "server.hpp"

#include "session.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uri.hpp>

#include <rawstor/rawstor.h>

#include <arpa/inet.h>

#include <netinet/tcp.h>

#include <sys/socket.h>

#include <unistd.h>

#include <functional>
#include <sstream>
#include <string>

#include <cstring>

namespace {

typedef std::function<void(size_t, int)> IOCallback;

int io_callback(size_t result, int error, void* data) {
    std::unique_ptr<IOCallback> cb(static_cast<IOCallback*>(data));

    try {
        (*cb)(result, error);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EIO;
}

} // namespace

namespace rawstor {
namespace ostbackend {

Server::Server(
    unsigned int queue_size, const std::string& addr, unsigned int port,
    const char* location
) :
    _queue(nullptr),
    _fd(-1),
    _locations(rawstd::URI::uriv(location)),
    _accept_event(nullptr) {

    int res = rawstor_initialize(nullptr);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    try {
        res = rawio_queue_create(queue_size, &_queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        _fd = socket(AF_INET, SOCK_STREAM, 0);
        if (_fd == -1) {
            RAWSTD_THROW_ERRNO();
        }

        res = rawstd_socket_set_reuse(_fd);
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

        if (bind(_fd, reinterpret_cast<sockaddr*>(&sin), sizeof(sin)) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        if (listen(_fd, SOMAXCONN) == -1) {
            RAWSTD_THROW_ERRNO();
        }

        rawstd_info("Waiting for connections on %s:%u\n", addr.c_str(), port);
    } catch (...) {
        if (_fd != -1) {
            close(_fd);
        }
        if (_queue != nullptr) {
            rawio_queue_delete(_queue);
        }
        rawstor_terminate();
        throw;
    }
}

Server::~Server() {
    _sessions.clear();

    if (_fd != -1) {
        close(_fd);
    }

    if (_accept_event != nullptr) {
        int res = rawio_cancel(_queue, _accept_event);
        if (res < 0) {
            rawstd_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }

    rawio_queue_delete(_queue);

    rawstor_terminate();
}

int Server::_accept(int result, void* data) noexcept {
    Server* server = static_cast<Server*>(data);

    try {
        return server->_accept(result);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

int Server::_accept(int result) {
    if (result < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-result);
    }

    _add_session(result);

    return 0;
}

void Server::_add_session(int fd) {
    try {
        int res = rawstd_socket_set_nosigpipe(fd);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        _sessions.emplace(fd, std::make_shared<Session>(_queue, *this, fd));
    } catch (...) {
        close(fd);
        throw;
    }
}

void Server::del_session(int fd) noexcept {
    auto it = _sessions.find(fd);
    if (it != _sessions.end()) {
        _sessions.erase(it);
    }
}

void Server::loop() {
    int res =
        rawio_accept_multishot(_queue, _fd, _accept, this, &_accept_event);
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    while (true) {
        int res = rawio_wait(_queue);
        if (res == -EINTR) {
            break;
        }

        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
}

void Server::send_response(
    int fd, const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
    uint64_t hash
) {
    auto response =
        std::make_shared<RawstorOSTFrameResponse>((RawstorOSTFrameResponse){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = type,
                    .cid = cid,
                },
            .body = {
                .res = result,
                .hash = hash,
            },
        });

    auto cb =
        std::make_unique<IOCallback>([this, fd,
                                      response](size_t result, int error) {
            if (!error) {
                error = validate_result(fd, sizeof(*response), result);
            }

            if (error) {
                rawstd_error("%s\n", strerror(error));
                del_session(fd);
            }
        });

    int res = rawio_send(
        _queue, fd, response.get(), sizeof(*response), RAWSTD_MSG_NOSIGNAL,
        io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

void Server::send_response(
    int fd, const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
    uint64_t hash, const std::shared_ptr<std::vector<unsigned char>>& data
) {
    auto response =
        std::make_shared<RawstorOSTFrameResponse>((RawstorOSTFrameResponse){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = type,
                    .cid = cid,
                },
            .body = {
                .res = result,
                .hash = hash,
            },
        });

    auto iov = std::make_shared<std::vector<iovec>>(std::vector<iovec>{
        {
            .iov_base = response.get(),
            .iov_len = sizeof(*response),
        },
        {
            .iov_base = data->data(),
            .iov_len = data->size(),
        },
    });

    auto msg = std::make_shared<msghdr>((msghdr){
        .msg_name = nullptr,
        .msg_namelen = 0,
        .msg_iov = iov->data(),
        .msg_iovlen = iov->size(),
        .msg_control = nullptr,
        .msg_controllen = 0,
        .msg_flags = 0,
    });

    auto cb = std::make_unique<IOCallback>([this, fd, data, response, iov,
                                            msg](size_t result, int error) {
        if (!error) {
            error =
                validate_result(fd, sizeof(*response) + data->size(), result);
        }

        if (error) {
            rawstd_error("%s\n", strerror(error));
            del_session(fd);
        }
    });

    int res = rawio_sendmsg(
        _queue, fd, msg.get(), RAWSTD_MSG_NOSIGNAL, io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

} // namespace ostbackend
} // namespace rawstor
