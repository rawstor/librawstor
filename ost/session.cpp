#include "session.hpp"

#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawstor.h>

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
    RawIOQueue* queue, int fd, const RawstorOSTCommandType& type, uint16_t cid,
    int32_t result, uint64_t hash
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
        std::make_unique<IOCallback>([fd, response](size_t result, int error) {
            if (!error) {
                error = validate_result(fd, sizeof(*response), result);
            }

            if (error) {
                rawstd_error("%s\n", strerror(error));
            }
        });

    int res = rawio_write(
        queue, fd, response.get(), sizeof(*response), io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

void send_response(
    RawIOQueue* queue, int fd, const RawstorOSTCommandType& type, uint16_t cid,
    int32_t result, uint64_t hash,
    const std::shared_ptr<std::vector<unsigned char>>& data
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

    auto cb = std::make_unique<IOCallback>([fd, data, response,
                                            iov](size_t result, int error) {
        if (!error) {
            error =
                validate_result(fd, sizeof(*response) + data->size(), result);
        }

        if (error) {
            rawstd_error("%s\n", strerror(error));
        }
    });

    int res = rawio_writev(
        queue, fd, iov->data(), iov->size(), io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

/*
 * Completion context for async object operations (allocate/release).
 * The session may be destroyed while the operation is in flight; alive
 * expires with it, in which case the response must not be sent: fd may
 * already be closed or reused by another session.
 */
struct OpCtx {
    RawIOQueue* queue;
    int fd;
    RawstorOSTCommandType cmd;
    uint16_t cid;
    std::weak_ptr<int> alive;
};

struct OpenCtx {
    RawIOQueue* queue;
    int fd;
    uint16_t cid;
    std::weak_ptr<int> alive;
    rawstor::ostbackend::Session* session;
};

int op_complete(int result, void* data) noexcept {
    std::unique_ptr<OpCtx> ctx(static_cast<OpCtx*>(data));

    if (ctx->alive.expired()) {
        return 0;
    }

    try {
        send_response(ctx->queue, ctx->fd, ctx->cmd, ctx->cid, result, 0);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

struct SpecCtx {
    RawIOQueue* queue;
    int fd;
    uint16_t cid;
    std::weak_ptr<int> alive;
    uint8_t obj_id[16];
    RawstorObjectMeta meta;
};

int spec_complete(int result, void* data) noexcept {
    std::unique_ptr<SpecCtx> ctx(static_cast<SpecCtx*>(data));

    if (ctx->alive.expired()) {
        return 0;
    }

    try {
        /* Error responses carry no metadata payload. */
        if (result < 0) {
            send_response(
                ctx->queue, ctx->fd, RAWSTOR_CMD_SPEC, ctx->cid, result, 0
            );
            return 0;
        }

        RawstorOSTFrameMetaBody body{};
        memcpy(body.obj_id, ctx->obj_id, sizeof(body.obj_id));
        body.size = ctx->meta.size;
        body.epoch = ctx->meta.epoch;
        body.sync_id = ctx->meta.sync_id;
        memcpy(
            body.sync_id_history, ctx->meta.sync_id_history,
            sizeof(body.sync_id_history)
        );
        body.state = ctx->meta.state;

        auto payload =
            std::make_shared<std::vector<unsigned char>>(sizeof(body));
        memcpy(payload->data(), &body, sizeof(body));

        send_response(
            ctx->queue, ctx->fd, RAWSTOR_CMD_SPEC, ctx->cid, result,
            rawstd_hash_scalar(payload->data(), payload->size()), payload
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

} // namespace

namespace rawstor {
namespace ostbackend {

Session::Session(RawIOQueue* queue, Server& server, int fd) :
    _queue(queue),
    _server(server),
    _fd(fd),
    _recv_event(nullptr),
    _next(&Session::_recv_head),
    _object(nullptr),
    _alive(std::make_shared<int>(0)),
    _open_pending(false) {
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
    case RAWSTOR_CMD_FLUSH:
        return sizeof(RawstorOSTFrameIOBody);
    case RAWSTOR_CMD_SET_OBJECT:
    case RAWSTOR_CMD_ALLOCATE:
    case RAWSTOR_CMD_RELEASE:
    case RAWSTOR_CMD_SPEC:
        return sizeof(RawstorOSTFrameBasicBody);
    case RAWSTOR_CMD_SET_STATE:
        return sizeof(RawstorOSTFrameMetaBody);
    }

    _unknown(_request_head);

    /*
     * The body length of the unknown command is not known, so the stream
     * position is lost: consume and ignore everything until the deferred
     * close lands. Parsing must not resume — payload bytes could otherwise
     * be executed as fabricated frames.
     */
    _next = &Session::_recv_ignore;

    return sizeof(RawstorOSTFrameHead);
}

ssize_t Session::_recv_ignore(const iovec*, unsigned int, size_t) {
    _next = &Session::_recv_ignore;

    return sizeof(RawstorOSTFrameHead);
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

    case RAWSTOR_CMD_SET_STATE:
        if (result != sizeof(_request_body.meta)) {
            rawstd_error(
                "fd %d: Unexpected request body size: %zu != %zu\n", _fd,
                result, sizeof(_request_body.meta)
            );

            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        rawstd_iovec_to_buf(
            iov, niov, 0, &_request_body.meta, sizeof(_request_body.meta)
        );

        _set_state(_request_head, _request_body.meta);

        return sizeof(RawstorOSTFrameHead);

    case RAWSTOR_CMD_FLUSH:
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

        _flush(_request_head, _request_body.io);

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

    auto ctx = std::make_unique<OpCtx>(
        OpCtx{_queue, _fd, RAWSTOR_CMD_ALLOCATE, head.cid, _alive}
    );

    int res = rawstor_object_create_async(
        _queue, rawstd::URI::uris(targets).c_str(), &spec, op_complete,
        ctx.get()
    );
    if (res < 0) {
        send_response(_queue, _fd, RAWSTOR_CMD_ALLOCATE, head.cid, res, 0);
        return;
    }

    ctx.release();
}

void Session::_release(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = _targets(uuid);

    auto ctx = std::make_unique<OpCtx>(
        OpCtx{_queue, _fd, RAWSTOR_CMD_RELEASE, head.cid, _alive}
    );

    int res = rawstor_object_remove_async(
        _queue, rawstd::URI::uris(targets).c_str(), op_complete, ctx.get()
    );
    if (res < 0) {
        send_response(_queue, _fd, RAWSTOR_CMD_RELEASE, head.cid, res, 0);
        return;
    }

    ctx.release();
}

int Session::_open_complete(
    RawstorObject* object, int result, void* data
) noexcept {
    std::unique_ptr<OpenCtx> ctx(static_cast<OpenCtx*>(data));

    if (ctx->alive.expired()) {
        if (object != nullptr) {
            int res = rawstor_object_close(object);
            if (res < 0) {
                rawstd_error(
                    "Failed to close orphaned object: %s\n", strerror(-res)
                );
            }
        }
        return 0;
    }

    ctx->session->_open_pending = false;

    if (result == 0) {
        ctx->session->_object = object;
    }

    try {
        send_response(
            ctx->queue, ctx->fd, RAWSTOR_CMD_SET_OBJECT, ctx->cid, result, 0
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

void Session::_set_object(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    if (_open_pending) {
        send_response(_queue, _fd, RAWSTOR_CMD_SET_OBJECT, head.cid, -EBUSY, 0);
        return;
    }

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

    auto ctx =
        std::make_unique<OpenCtx>(OpenCtx{_queue, _fd, head.cid, _alive, this});

    int res = rawstor_object_open_async(
        _queue, rawstd::URI::uris(targets).c_str(), _open_complete, ctx.get()
    );
    if (res < 0) {
        send_response(_queue, _fd, RAWSTOR_CMD_SET_OBJECT, head.cid, res, 0);
        return;
    }

    _open_pending = true;
    ctx.release();
}

void Session::_read(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
) {
    if (_object == nullptr) {
        send_response(_queue, _fd, RAWSTOR_CMD_READ, head.cid, -EBADF, 0);
        return;
    }

    // 64MB limit
    if (body.len > (1ULL << 26)) {
        send_response(_queue, _fd, RAWSTOR_CMD_READ, head.cid, -EINVAL, 0);
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(body.len);

    auto cb = std::make_unique<Callback>(
        [queue = _queue, fd = _fd, cid = head.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            try {
                send_response(
                    queue, fd, RAWSTOR_CMD_READ, cid,
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
        send_response(_queue, _fd, RAWSTOR_CMD_READ, head.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_write(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body,
    const iovec* iov, unsigned int niov, size_t size
) {
    if (_object == nullptr) {
        send_response(_queue, _fd, RAWSTOR_CMD_WRITE, head.cid, -EBADF, 0);
        return;
    }

    // 64MB limit
    if (body.len > (1ULL << 26)) {
        send_response(_queue, _fd, RAWSTOR_CMD_WRITE, head.cid, -EINVAL, 0);
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
        send_response(_queue, _fd, RAWSTOR_CMD_WRITE, head.cid, -EIO, 0);
        return;
    }

    auto cb = std::make_unique<Callback>(
        [queue = _queue, fd = _fd, cid = head.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            try {
                send_response(
                    queue, fd, RAWSTOR_CMD_WRITE, cid,
                    error ? -error : static_cast<int32_t>(result),
                    error ? 0 : rawstd_hash_scalar(data->data(), data->size())
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_pwrite(
        _object, data->data(), data->size(), body.offset, callback, cb.get()
    );
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        send_response(_queue, _fd, RAWSTOR_CMD_WRITE, head.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_discard(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody&
) {
    send_response(_queue, _fd, RAWSTOR_CMD_DISCARD, head.cid, -ENOSYS, 0);
}

void Session::_spec(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = _targets(uuid);

    auto ctx = std::make_unique<SpecCtx>();
    ctx->queue = _queue;
    ctx->fd = _fd;
    ctx->cid = head.cid;
    ctx->alive = _alive;
    memcpy(ctx->obj_id, body.obj_id, sizeof(ctx->obj_id));

    int res = rawstor_object_meta_async(
        _queue, rawstd::URI::uris(targets).c_str(), &ctx->meta, spec_complete,
        ctx.get()
    );
    if (res < 0) {
        spec_complete(res, ctx.release());
        return;
    }

    ctx.release();
}

void Session::_set_state(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameMetaBody& body
) {
    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    RawstorObjectMeta meta{};
    meta.size = body.size;
    meta.epoch = body.epoch;
    meta.sync_id = body.sync_id;
    memcpy(
        meta.sync_id_history, body.sync_id_history, sizeof(meta.sync_id_history)
    );
    meta.state = body.state;

    std::vector<rawstd::URI> targets = _targets(uuid);

    auto ctx = std::make_unique<OpCtx>(
        OpCtx{_queue, _fd, RAWSTOR_CMD_SET_STATE, head.cid, _alive}
    );

    int res = rawstor_object_set_state_async(
        _queue, rawstd::URI::uris(targets).c_str(), &meta, op_complete,
        ctx.get()
    );
    if (res < 0) {
        send_response(_queue, _fd, RAWSTOR_CMD_SET_STATE, head.cid, res, 0);
        return;
    }

    ctx.release();
}

void Session::_flush(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody&
) {
    if (_object == nullptr) {
        send_response(_queue, _fd, RAWSTOR_CMD_FLUSH, head.cid, -EBADF, 0);
        return;
    }

    auto cb = std::make_unique<Callback>(
        [queue = _queue, fd = _fd,
         cid = head.cid](RawstorObject*, size_t, size_t, int error) {
            try {
                send_response(
                    queue, fd, RAWSTOR_CMD_FLUSH, cid, error ? -error : 0, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_flush(_object, callback, cb.get());
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        send_response(_queue, _fd, RAWSTOR_CMD_FLUSH, head.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_unknown(const RawstorOSTFrameHead& head) {
    rawstd_error("fd %d: Unexpected command: %u\n", _fd, head.cmd);

    /*
     * The body length of an unknown command is unknown, so the stream
     * position is lost: answer -ENOSYS and close the session once the
     * response is flushed.
     */
    auto response =
        std::make_shared<RawstorOSTFrameResponse>((RawstorOSTFrameResponse){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = head.cmd,
                    .cid = head.cid,
                },
            .body = {
                .res = -ENOSYS,
                .hash = 0,
            },
        });

    auto cb = std::make_unique<IOCallback>([server = &_server, fd = _fd,
                                            alive = std::weak_ptr<int>(_alive),
                                            response](size_t, int) {
        if (alive.expired()) {
            return;
        }
        server->del_session(fd);
    });

    int res = rawio_write(
        _queue, _fd, response.get(), sizeof(*response), io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
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
