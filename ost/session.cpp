#include "session.hpp"

#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

#include <sys/socket.h>

#include <functional>
#include <memory>
#include <sstream>
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
        rawstd_error("%s\n", e.what());
    }

    return 0;
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

void send_response(
    RawIOQueue* queue, int fd, rawstor::ostbackend::Server& server,
    const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
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
        std::make_unique<IOCallback>([fd, &server,
                                      response](size_t result, int error) {
            if (!error) {
                error = validate_result(fd, sizeof(*response), result);
            }

            if (error) {
                rawstd_error("%s\n", strerror(error));
                server.del_session(fd);
            }
        });

    int res = rawio_send(
        queue, fd, response.get(), sizeof(*response), RAWSTD_MSG_NOSIGNAL,
        io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

void send_response(
    RawIOQueue* queue, int fd, rawstor::ostbackend::Server& server,
    const RawstorOSTCommandType& type, uint16_t cid, int32_t result,
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

    auto cb = std::make_unique<IOCallback>([fd, &server, data, response, iov,
                                            msg](size_t result, int error) {
        if (!error) {
            error =
                validate_result(fd, sizeof(*response) + data->size(), result);
        }

        if (error) {
            rawstd_error("%s\n", strerror(error));
            server.del_session(fd);
        }
    });

    int res = rawio_sendmsg(
        queue, fd, msg.get(), RAWSTD_MSG_NOSIGNAL, io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

} // namespace

namespace rawstor {
namespace ostbackend {

Session::Session(RawIOQueue* queue, Server& server, int fd) :
    _queue(queue),
    _server(server),
    _fd(fd),
    _alive(std::make_shared<bool>(true)),
    _recv_event(nullptr),
    _next(&Session::_recv_head),
    _object(nullptr) {
    int res = rawio_recv_multishot(
        _queue, _fd, 1u << 17, 64 * 4, sizeof(_request_head), 0, _recv, this,
        &_recv_event
    );
    if (res < 0) {
        close(_fd);
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

Session::~Session() noexcept {
    *_alive = false;
    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            rawstd_error(
                "Failed to close object in session: %s\n", strerror(-res)
            );
        }
        _object = nullptr;
    }
    if (_recv_event != nullptr) {
        int res = rawio_cancel(_queue, _recv_event);
        if (res < 0) {
            rawstd_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }
    close(_fd);
}

ssize_t Session::_recv(
    const iovec* iov, unsigned int niov, size_t result, int error, void* data
) noexcept {
    if (error == ECANCELED) {
        return 0;
    }
    Session* session = static_cast<Session*>(data);
    try {
        return session->_recv(iov, niov, result, error);
    } catch (const std::system_error& e) {
        if (e.code().value() != EPIPE) {
            rawstd_error("%s\n", e.what());
        }
        session->_server.del_session(session->_fd);
        return 0;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        session->_server.del_session(session->_fd);
        return 0;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        session->_server.del_session(session->_fd);
        return 0;
    }
}

ssize_t
Session::_recv(const iovec* iov, unsigned int niov, size_t result, int error) {
    if (error) {
        _recv_event = nullptr;
        RAWSTD_THROW_SYSTEM_ERROR(error);
    }

    return (this->*_next)(iov, niov, result);
}

ssize_t
Session::_recv_head(const iovec* iov, unsigned int niov, size_t result) {
    if (result != sizeof(_request_head)) {
        rawstd_error(
            "fd %d: Unexpected request head size: %zu != %zu\n", _fd, result,
            sizeof(_request_head)
        );

        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    rawstd_iovec_to_buf(iov, niov, 0, &_request_head, sizeof(_request_head));

    if (_request_head.magic != RAWSTOR_MAGIC) {
        rawstd_error(
            "fd %d: Unexpected magic number: %x != %x\n", _fd,
            _request_head.magic, RAWSTOR_MAGIC
        );

        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    _next = &Session::_recv_body;

    rawstd_trace("head received: %d\n", _request_head.cmd);
    switch (_request_head.cmd) {
    case RAWSTOR_CMD_READ:
    case RAWSTOR_CMD_WRITE:
    case RAWSTOR_CMD_DISCARD:
        return sizeof(RawstorOSTFrameIOBody);
    case RAWSTOR_CMD_SET_OBJECT:
    case RAWSTOR_CMD_ALLOCATE:
    case RAWSTOR_CMD_RELEASE:
    case RAWSTOR_CMD_LIST:
    case RAWSTOR_CMD_SPEC:
    case RAWSTOR_CMD_LOCATION_INFO:
    case RAWSTOR_CMD_FLUSH:
        return sizeof(RawstorOSTFrameBasicBody);
    }

    {
        std::ostringstream oss;
        oss << "Unexpected command: " << _request_head.cmd;
        throw std::runtime_error(oss.str());
    }
}

ssize_t
Session::_recv_body(const iovec* iov, unsigned int niov, size_t result) {
    _next = &Session::_recv_head;

    switch (_request_head.cmd) {
    case RAWSTOR_CMD_SET_OBJECT:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _set_object(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_READ:
        if (result != sizeof(_request_body.io)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.io)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.io, sizeof(_request_body.io)
        );

        _read(_request_head, _request_body.io);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_WRITE:
        if (result != sizeof(_request_body.io)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.io)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.io, sizeof(_request_body.io)
        );

        _next = &Session::_recv_data;

        return _request_body.io.len;

    case RAWSTOR_CMD_DISCARD:
        if (result != sizeof(_request_body.io)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.io)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.io, sizeof(_request_body.io)
        );

        _discard(_request_head, _request_body.io);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_LIST:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _list(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_ALLOCATE:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _allocate(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_RELEASE:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _release(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_SPEC:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _spec(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_LOCATION_INFO:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _info(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_FLUSH:
        if (result != sizeof(_request_body.basic)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.basic)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.basic, sizeof(_request_body.basic)
        );

        _flush(_request_head, _request_body.basic);

        return sizeof(RawstorOSTFrameHead);
    }

    {
        std::ostringstream oss;
        oss << "Unexpected command: " << _request_head.cmd;
        throw std::runtime_error(oss.str());
    }
}

ssize_t
Session::_recv_data(const iovec* iov, unsigned int niov, size_t result) {
    _next = &Session::_recv_head;

    if (result != _request_body.io.len) {
        rawstd_error(
            "fd %d: Unexpected request data size: %zu != %u\n", _fd, result,
            _request_body.io.len
        );

        RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
    }

    _write(_request_head, _request_body.io, iov, niov, result);

    return sizeof(RawstorOSTFrameHead);
}

void Session::_list(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        _object = nullptr;
    }

    RawstorPaginationToken token;
    memcpy(token.bytes, body.obj_id, sizeof(body.obj_id));

    RawstorStringList* targets;
    int result = rawstor_object_list(
        rawstd::URI::uris(_server.locations()).c_str(), body.val, &targets,
        &token
    );
    if (result < 0) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_LIST, head.cid, result, 0
        );
        return;
    }

    try {
        auto data = std::make_shared<std::vector<unsigned char>>(
            sizeof(RawstdUUID) * (rawstor_string_list_size(targets) + 1)
        );
        RawstdUUID* out_it =
            static_cast<RawstdUUID*>(static_cast<void*>(data->data()));
        for (const char** in_it = rawstor_string_list_iter(targets);
             in_it != NULL; in_it = rawstor_string_list_next(in_it), ++out_it) {
            rawstd::URI target(*in_it);
            int res = rawstd_uuid_from_string(
                out_it, target.path().filename().c_str()
            );
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }
        memcpy(out_it, &token, sizeof(token));
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_LIST, head.cid, data->size(), 0,
            data
        );
    } catch (...) {
        rawstor_string_list_delete(targets);
        throw;
    }
    rawstor_string_list_delete(targets);
}

void Session::_allocate(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        _object = nullptr;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    RawstorObjectSpec spec{
        .size = body.val,
    };

    std::vector<rawstd::URI> targets = _targets(uuid);

    int result =
        rawstor_object_create(rawstd::URI::uris(targets).c_str(), &spec);

    send_response(
        _queue, _fd, _server, RAWSTOR_CMD_ALLOCATE, head.cid, result, 0
    );
}

void Session::_release(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = _targets(uuid);

    int result = rawstor_object_remove(rawstd::URI::uris(targets).c_str());

    send_response(
        _queue, _fd, _server, RAWSTOR_CMD_RELEASE, head.cid, result, 0
    );
}

void Session::_spec(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = _targets(uuid);

    RawstorObjectSpec spec{};
    int result = rawstor_object_spec(rawstd::URI::uris(targets).c_str(), &spec);
    if (result < 0) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_SPEC, head.cid, result, 0
        );
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(sizeof(spec));
    memcpy(data->data(), &spec, sizeof(spec));

    send_response(
        _queue, _fd, _server, RAWSTOR_CMD_SPEC, head.cid, data->size(), 0, data
    );
}

void Session::_info(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody&
) {
    RawstorLocationInfo info{};
    int result = rawstor_location_info(
        rawstd::URI::uris(_server.locations()).c_str(), &info
    );
    if (result < 0) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_LOCATION_INFO, head.cid, result, 0
        );
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(sizeof(info));
    memcpy(data->data(), &info, sizeof(info));

    send_response(
        _queue, _fd, _server, RAWSTOR_CMD_LOCATION_INFO, head.cid, data->size(),
        0, data
    );
}

void Session::_set_object(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    if (_object != nullptr) {
        int res = rawstor_object_close(_object);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        _object = nullptr;
    }

    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = _targets(uuid);

    int result = rawstor_object_open(
        _queue, rawstd::URI::uris(targets).c_str(), &_object
    );

    send_response(
        _queue, _fd, _server, RAWSTOR_CMD_SET_OBJECT, head.cid, result, 0
    );
}

void Session::_read(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
) {
    if (_object == nullptr) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_READ, head.cid, -EBADF, 0
        );
        return;
    }

    // 64MB limit
    if (body.len > (1ULL << 26)) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_READ, head.cid, -EINVAL, 0
        );
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(body.len);

    auto cb = std::make_unique<Callback>(
        [queue = _queue, fd = _fd, &server = _server, alive = _alive,
         cid = head.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            if (!*alive) {
                return;
            }
            try {
                send_response(
                    queue, fd, server, RAWSTOR_CMD_READ, cid,
                    error ? -error : static_cast<int32_t>(result),
                    error ? 0 : rawstd_hash_scalar(data->data(), data->size()),
                    data
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_pread(
        _object, data->data(), data->size(), body.offset, callback, cb.get()
    );
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        send_response(_queue, _fd, _server, RAWSTOR_CMD_READ, head.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_write(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body,
    const iovec* iov, unsigned int niov, size_t size
) {
    if (_object == nullptr) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_WRITE, head.cid, -EBADF, 0
        );
        return;
    }

    // 64MB limit
    if (body.len > (1ULL << 26)) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_WRITE, head.cid, -EINVAL, 0
        );
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(size);
    rawstd_iovec_to_buf(iov, niov, 0, data->data(), size);

    uint64_t hash = rawstd_hash_scalar(data->data(), data->size());

    if (hash != body.hash) {
        rawstd_error(
            "Hash mismatch: %llx != %llx\n",
            static_cast<unsigned long long>(hash),
            static_cast<unsigned long long>(body.hash)
        );
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_WRITE, head.cid, -EIO, 0
        );
        return;
    }

    auto cb = std::make_unique<Callback>(
        [queue = _queue, fd = _fd, &server = _server, alive = _alive,
         cid = head.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            if (!*alive) {
                return;
            }
            try {
                send_response(
                    queue, fd, server, RAWSTOR_CMD_WRITE, cid,
                    error ? -error : static_cast<int32_t>(result),
                    error ? 0 : rawstd_hash_scalar(data->data(), data->size())
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_pwrite(
        _object, data->data(), data->size(), body.offset, body.sync, callback,
        cb.get()
    );
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_WRITE, head.cid, res, 0
        );
    } else {
        cb.release();
    }
}

void Session::_flush(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody&
) {
    if (_object == nullptr) {
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_FLUSH, head.cid, -EBADF, 0
        );
        return;
    }

    auto cb = std::make_unique<Callback>(
        [queue = _queue, fd = _fd, &server = _server, alive = _alive,
         cid = head.cid](RawstorObject*, size_t, size_t, int error) {
            if (!*alive) {
                return;
            }
            try {
                send_response(
                    queue, fd, server, RAWSTOR_CMD_FLUSH, cid,
                    error ? -error : 0, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_flush(_object, callback, cb.get());
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        send_response(
            _queue, _fd, _server, RAWSTOR_CMD_FLUSH, head.cid, res, 0
        );
    } else {
        cb.release();
    }
}

void Session::_discard(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody&
) {
    send_response(
        _queue, _fd, _server, RAWSTOR_CMD_DISCARD, head.cid, -ENOSYS, 0
    );
}

std::vector<rawstd::URI> Session::_targets(const RawstdUUID& uuid) {
    RawstdUUIDString uuid_string;
    rawstd_uuid_to_string(&uuid, &uuid_string);

    std::vector<rawstd::URI> ret;
    ret.reserve(_server.locations().size());
    for (const auto& location : _server.locations()) {
        ret.emplace_back(location, uuid_string);
    }

    return ret;
}

} // namespace ostbackend
} // namespace rawstor
