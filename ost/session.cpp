#include "session.hpp"

#include "server.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.hpp>
#include <rawstorstd/uri.hpp>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/ost_protocol.h>
#include <rawstor/rawstor.h>

#include <functional>
#include <memory>
#include <vector>

#include <cstring>

namespace {

typedef std::function<void(size_t, int)> IOCallback;

typedef std::function<void(RawstorObject*, size_t, size_t, int)> Callback;

int io_callback(size_t result, int error, void* data) {
    std::unique_ptr<IOCallback> cb(static_cast<IOCallback*>(data));

    try {
        (*cb)(result, error);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    }
}

int callback(
    RawstorObject* object, size_t size, size_t result, int error, void* data
) {
    std::unique_ptr<Callback> cb(static_cast<Callback*>(data));

    try {
        (*cb)(object, size, result, error);
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
    }

    return 0;
}

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstor_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EIO;
}

void send_response(
    int fd, const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
    uint64_t hash
) {
    auto response =
        std::make_shared<RawstorOSTFrameResponse>((RawstorOSTFrameResponse){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = type,
                },
            .body = {
                .cid = cid,
                .res = result,
                .hash = hash,
            },
        });

    auto cb =
        std::make_unique<IOCallback>([fd, response](size_t result, int error) {
            if (!error) {
                error = validate_result(fd, sizeof(*response), result);
            }

            if (error) {
                rawstor_error("%s\n", strerror(error));
                int res = ::close(fd);
                if (res == -1) {
                    RAWSTOR_THROW_ERRNO();
                }
            }
        });

    int res = rawstor_fd_write(
        fd, response.get(), sizeof(*response), io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

void send_response(
    int fd, const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
    uint64_t hash, const std::shared_ptr<std::vector<unsigned char>>& data
) {
    auto response =
        std::make_shared<RawstorOSTFrameResponse>((RawstorOSTFrameResponse){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = type,
                },
            .body = {
                .cid = cid,
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

    auto cb = std::make_unique<IOCallback>([fd, data, response,
                                            iov](size_t result, int error) {
        if (!error) {
            error =
                validate_result(fd, sizeof(*response) + data->size(), result);
        }

        if (error) {
            rawstor_error("%s\n", strerror(error));
            int res = close(fd);
            if (res == -1) {
                int errsv = errno;
                errno = 0;
                rawstor_error("%s\n", strerror(errsv));
            }
        }
    });

    int res =
        rawstor_fd_writev(fd, iov->data(), iov->size(), io_callback, cb.get());
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

} // namespace

namespace rawstor {
namespace ostbackend {

Session::Session(Server& server, int fd) :
    _server(server),
    _fd(fd),
    _recv_event(nullptr),
    _next(&Session::_recv_head),
    _object(nullptr) {
    int res = rawstor_fd_recv_multishot(
        _fd, 1u << 17, 64 * 4, sizeof(_request_head), 0, _recv, this,
        &_recv_event
    );
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

Session::~Session() noexcept {
    if (_object != nullptr) {
        rawstor_object_close(_object);
        _object = nullptr;
    }
    if (_recv_event != nullptr) {
        int res = rawstor_fd_cancel(_recv_event);
        if (res < 0) {
            if (res != -ENOENT) {
                rawstor_error("Failed to cancel event: %s\n", strerror(-res));
            }
        }
    }
    close(_fd);
}

ssize_t Session::_recv(
    const iovec* iov, unsigned int niov, size_t result, int error, void* data
) noexcept {
    Session* session = static_cast<Session*>(data);
    try {
        return session->_recv(iov, niov, result, error);
    } catch (const std::exception& e) {
        rawstor_error("%s\n", e.what());
        session->_server.del_session(session->_fd);
        return 0;
    } catch (...) {
        rawstor_error("Unexpected error\n");
        session->_server.del_session(session->_fd);
        return 0;
    }
}

ssize_t
Session::_recv(const iovec* iov, unsigned int niov, size_t result, int error) {
    if (error) {
        _recv_event = nullptr;
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    return (this->*_next)(iov, niov, result);
}

ssize_t
Session::_recv_head(const iovec* iov, unsigned int niov, size_t result) {
    if (result != sizeof(_request_head)) {
        rawstor_error(
            "fd %d: Unexpected request head size: %zu != %zu\n", _fd, result,
            sizeof(_request_head)
        );

        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    rawstor_iovec_to_buf(iov, niov, 0, &_request_head, sizeof(_request_head));

    if (_request_head.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "fd %d: Unexpected magic number: %x != %x\n", _fd,
            _request_head.magic, RAWSTOR_MAGIC
        );
        return -EPROTO;
    }

    _next = &Session::_recv_body;

    rawstor_trace("head received: %d\n", _request_head.cmd);
    switch (_request_head.cmd) {
    case RAWSTOR_CMD_SET_OBJECT:
        return sizeof(RawstorOSTFrameBasicBody);
    case RAWSTOR_CMD_READ:
    case RAWSTOR_CMD_WRITE:
    case RAWSTOR_CMD_DISCARD:
        return sizeof(RawstorOSTFrameIOBody);
    }

    return 0;
}

ssize_t
Session::_recv_body(const iovec* iov, unsigned int niov, size_t result) {
    _next = &Session::_recv_head;

    switch (_request_head.cmd) {
    case RAWSTOR_CMD_SET_OBJECT:
        if (result != sizeof(_request_body.basic)) {
            rawstor_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstor_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _set_object(_request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_READ:
        if (result != sizeof(_request_body.io)) {
            rawstor_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.io)
            );

            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstor_iovec_to_buf(
            iov, niov, 0, &_request_body.io, sizeof(_request_body.io)
        );

        _read(_request_body.io);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_WRITE:
        if (result != sizeof(_request_body.io)) {
            rawstor_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.io)
            );

            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstor_iovec_to_buf(
            iov, niov, 0, &_request_body.io, sizeof(_request_body.io)
        );

        _next = &Session::_recv_data;

        return _request_body.io.len;

    case RAWSTOR_CMD_DISCARD:
        if (result != sizeof(_request_body.io)) {
            rawstor_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.io)
            );

            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstor_iovec_to_buf(
            iov, niov, 0, &_request_body.io, sizeof(_request_body.io)
        );

        _discard(_request_body.io);

        return sizeof(RawstorOSTFrameHead);
    }

    return 0;
}

ssize_t
Session::_recv_data(const iovec* iov, unsigned int niov, size_t result) {
    _next = &Session::_recv_head;

    if (result != _request_body.io.len) {
        rawstor_error(
            "fd %d: Unexpected request data size: %zu != %u\n", _fd, result,
            _request_body.io.len
        );

        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    _write(_request_body.io, iov, niov, result);

    return sizeof(RawstorOSTFrameHead);
}

void Session::_set_object(const RawstorOSTFrameBasicBody& request) {
    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
        _object = nullptr;
    }

    RawstorUUID uuid;
    memcpy(uuid.bytes, request.obj_id, sizeof(request.obj_id));

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstor::URI> object_uris;
    object_uris.reserve(_server.uris().size());
    for (const auto& uri : _server.uris()) {
        rawstor::URI object_uri = rawstor::URI(uri, uuid_string);
        object_uris.push_back(object_uri);
    }

    int result =
        rawstor_object_open(rawstor::URI::uris(object_uris).c_str(), &_object);

    send_response(_fd, RAWSTOR_CMD_SET_OBJECT, 0, result, 0);
}

void Session::_read(const RawstorOSTFrameIOBody& request) {
    auto data = std::make_shared<std::vector<unsigned char>>(request.len);

    auto cb = std::make_unique<Callback>(
        [fd = _fd, cid = request.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            try {
                send_response(
                    fd, RAWSTOR_CMD_READ, cid,
                    error ? -error : static_cast<int>(result),
                    error ? 0 : rawstor_hash_scalar(data->data(), data->size()),
                    data
                );
            } catch (...) {
                int res = close(fd);
                if (res == -1) {
                    int errsv = errno;
                    errno = 0;
                    rawstor_error("%s\n", strerror(errsv));
                }
                throw;
            }
        }
    );

    int res = rawstor_object_pread(
        _object, data->data(), data->size(), request.offset, callback, cb.get()
    );
    if (res < 0) {
        rawstor_warning("%s\n", strerror(-res));
        send_response(_fd, RAWSTOR_CMD_READ, request.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_write(
    const RawstorOSTFrameIOBody& request, const iovec* iov, unsigned int niov,
    size_t size
) {
    auto data = std::make_shared<std::vector<unsigned char>>(size);
    rawstor_iovec_to_buf(iov, niov, 0, data->data(), size);

    auto cb = std::make_unique<Callback>(
        [fd = _fd, cid = request.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            try {
                send_response(
                    fd, RAWSTOR_CMD_WRITE, cid,
                    error ? -error : static_cast<int>(result),
                    error ? 0 : rawstor_hash_scalar(data->data(), data->size())
                );
            } catch (...) {
                int res = close(fd);
                if (res == -1) {
                    int errsv = errno;
                    errno = 0;
                    rawstor_error("%s\n", strerror(errsv));
                }
                throw;
            }
        }
    );

    int res = rawstor_object_pwrite(
        _object, data->data(), data->size(), request.offset, callback, cb.get()
    );
    if (res < 0) {
        rawstor_warning("%s\n", strerror(-res));
        send_response(_fd, RAWSTOR_CMD_WRITE, request.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_discard(const RawstorOSTFrameIOBody&) {
    throw std::runtime_error("Not implemented");
}

} // namespace ostbackend
} // namespace rawstor
