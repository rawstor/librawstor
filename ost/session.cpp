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

#include <memory>

#include <cstring>

namespace {

class SessionOp {
protected:
    int _fd;
    RawstorOSTFrameResponse _response;

public:
    static int callback(size_t result, int error, void* data) {
        std::unique_ptr<SessionOp> op(static_cast<SessionOp*>(data));

        try {
            (*op)(result, error);
            return 0;
        } catch (const std::system_error& e) {
            return -e.code().value();
        }
    }

    SessionOp(int fd, RawstorOSTCommandType cmd, uint16_t cid, int32_t res) :
        _fd(fd),
        _response{
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = cmd,
                },
            .cid = cid,
            .res = res,
            .hash = 0,
        } {}

    SessionOp(const SessionOp&) = delete;
    SessionOp(SessionOp&&) = delete;
    virtual ~SessionOp() = default;

    SessionOp& operator=(const SessionOp&) = delete;
    SessionOp& operator=(SessionOp&&) = delete;

    virtual void operator()(size_t, int error) = 0;
};

class SessionOpSetObject final : SessionOp {
public:
    SessionOpSetObject(int fd, int32_t res) :
        SessionOp(fd, RAWSTOR_CMD_SET_OBJECT, 0, res) {}

    void process() {
        int res = rawstor_fd_write(
            _fd, &_response, sizeof(_response), callback, this
        );
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    void operator()(size_t, int error) override {
        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }
    }
};

class SessionOpRead final : SessionOp {
private:
    RawstorObject* _object;
    std::vector<char> _buf;
    iovec _iov[2];
    off_t _offset;

    int _io_cb(RawstorObject*, size_t, size_t result, int error) {
        if (error) {
            _response.hash = 0;
            _response.res = -error;
            _iov[1].iov_len = 0;
        } else {
            _response.hash = rawstor_hash_scalar(_buf.data(), result);
            _response.res = result;
            _iov[1].iov_len = result;
        }

        int res = rawstor_fd_writev(_fd, _iov, 2, callback, this);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        return 0;
    }

public:
    static int io_cb(
        RawstorObject* object, size_t size, size_t result, int error, void* data
    ) {
        try {
            std::unique_ptr<SessionOpRead> op(
                static_cast<SessionOpRead*>(data)
            );
            int ret = op->_io_cb(object, size, result, error);
            if (ret >= 0) {
                op.release();
            }
            return ret;
        } catch (const std::system_error& e) {
            return -e.code().value();
        }
    }

    SessionOpRead(
        RawstorObject* object, int fd, uint16_t cid, size_t size, off_t offset
    ) :
        SessionOp(fd, RAWSTOR_CMD_READ, cid, 0),
        _object(object),
        _buf(size),
        _iov{
            {
                .iov_base = &_response,
                .iov_len = sizeof(_response),
            },
            {
                .iov_base = _buf.data(),
                .iov_len = 0,
            }
        },
        _offset(offset) {}

    void process() {
        int res = rawstor_object_pread(
            _object, _buf.data(), _buf.size(), _offset, io_cb, this
        );
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    void operator()(size_t, int error) override {
        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }
    }
};

class SessionOpWrite final : SessionOp {
private:
    RawstorObject* _object;
    std::vector<char> _buf;
    off_t _offset;

    int _io_cb(RawstorObject*, size_t, size_t result, int error) {
        if (error) {
            _response.hash = 0;
            _response.res = -error;
        } else {
            _response.hash = rawstor_hash_scalar(_buf.data(), _buf.size());
            _response.res = result;
        }

        int res = rawstor_fd_write(
            _fd, &_response, sizeof(_response), callback, this
        );
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        return 0;
    }

public:
    static int io_cb(
        RawstorObject* object, size_t size, size_t result, int error, void* data
    ) {
        try {
            std::unique_ptr<SessionOpWrite> op(
                static_cast<SessionOpWrite*>(data)
            );
            int ret = op->_io_cb(object, size, result, error);
            if (ret >= 0) {
                op.release();
            }
            return ret;
        } catch (const std::system_error& e) {
            return -e.code().value();
        }
    }

    SessionOpWrite(
        RawstorObject* object, int fd, uint16_t cid, off_t offset,
        const iovec* iov, unsigned int niov, size_t size
    ) :
        SessionOp(fd, RAWSTOR_CMD_WRITE, cid, 0),
        _object(object),
        _buf(size),
        _offset(offset) {
        rawstor_iovec_to_buf(iov, niov, 0, _buf.data(), size);
        _response.hash = rawstor_hash_scalar(_buf.data(), _buf.size());
    }

    void process() {
        int res = rawstor_object_pwrite(
            _object, _buf.data(), _buf.size(), _offset, io_cb, this
        );
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }

    void operator()(size_t, int error) override {
        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }
    }
};

} // namespace

namespace rawstor {
namespace ostbackend {

Session::Session(Server& server, int fd) :
    _server(server),
    _fd(fd),
    _recv_event(nullptr),
    _next(SON_HEAD),
    _object(nullptr) {
    int res = rawstor_fd_recv_multishot(
        _fd, 1u << 17, 64 * 4, sizeof(_request_head), 0, _recv, this,
        &_recv_event
    );
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}

Session::~Session() {
    if (_object != nullptr) {
        rawstor_object_close(_object);
        _object = nullptr;
    }
    if (_recv_event != nullptr) {
        int res = rawstor_fd_cancel(_recv_event);
        if (res < 0) {
            rawstor_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }
    close(_fd);
    _server.del_session(_fd);
}

ssize_t Session::_recv(
    const iovec* iov, unsigned int niov, size_t result, int error, void* data
) {
    Session* session = static_cast<Session*>(data);
    return session->_recv(iov, niov, result, error);
}

ssize_t
Session::_recv(const iovec* iov, unsigned int niov, size_t result, int error) {
    if (error) {
        if (error == EPIPE) {
            _server.del_session(_fd);
            return 0;
        }
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    switch (_next) {
    case SON_HEAD:
        return _recv_head(iov, niov, result);
    case SON_BODY:
        return _recv_body(iov, niov, result);
    case SON_DATA:
        return _recv_data(iov, niov, result);
    }

    return 0;
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

    _next = SON_BODY;

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
    _next = SON_HEAD;

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

        _next = SON_DATA;

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
    _next = SON_HEAD;

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

    int res =
        rawstor_object_open(rawstor::URI::uris(object_uris).c_str(), &_object);

    std::unique_ptr<SessionOpSetObject> op =
        std::make_unique<SessionOpSetObject>(_fd, res);
    op->process();
    op.release();
}

void Session::_read(const RawstorOSTFrameIOBody& request) {
    std::unique_ptr<SessionOpRead> op = std::make_unique<SessionOpRead>(
        _object, _fd, request.cid, request.len, request.offset
    );

    op->process();
    op.release();
}

void Session::_write(
    const RawstorOSTFrameIOBody& request, const iovec* iov, unsigned int niov,
    size_t size
) {
    std::unique_ptr<SessionOpWrite> op = std::make_unique<SessionOpWrite>(
        _object, _fd, request.cid, request.offset, iov, niov, size
    );

    op->process();
    op.release();
}

void Session::_discard(const RawstorOSTFrameIOBody&) {
    throw std::runtime_error("Not implemented");
}

} // namespace ostbackend
} // namespace rawstor
