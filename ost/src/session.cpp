#include <ost/session.hpp>

#include <ost/server.hpp>

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

#include <cerrno>
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

} // namespace

namespace rawstor {
namespace ostbackend {

std::shared_ptr<Session>
Session::create(RawIOQueue* queue, Server& server, int fd) {
    // _arm_recv() needs weak_from_this(), which isn't wired up yet while
    // the constructor itself is still running (enable_shared_from_this's
    // weak_ptr is only set by make_shared() right before returning) --
    // arm the recv here instead. If it throws, `session` was fully
    // constructed already, so its own destructor (which closes fd) runs
    // normally during unwinding.
    std::shared_ptr<Session> session =
        std::make_shared<Session>(Private(), queue, server, fd);
    session->_arm_recv();
    return session;
}

Session::Session(Private, RawIOQueue* queue, Server& server, int fd) :
    _queue(queue),
    _server(server),
    _fd(fd),
    _recv_event(nullptr),
    _next(&Session::_recv_head),
    _object(nullptr),
    _writes_in_flight(0),
    _pending_writes_bytes(0),
    _open_pending(false) {
}

void Session::_arm_recv() {
    // A multishot recv's terminal completion (peer disconnect -> EPIPE,
    // ENOBUFS, ... -- any error is terminal, not just ECANCELED; see
    // rawio.h) can already be sitting unprocessed in the completion queue
    // by the time this Session is destroyed, so ~Session()'s rawio_cancel()
    // can be too late to stop it (see there). Passing a weak_ptr instead of a
    // raw `this` lets that final callback tell a since-destroyed Session
    // apart from a live one instead of touching freed memory.
    auto holder = std::make_unique<std::weak_ptr<Session>>(weak_from_this());
    int res = rawio_recv_multishot(
        _queue, _fd, 1u << 17, 64 * 4, sizeof(_request_head), 0, _recv,
        holder.get(), &_recv_event
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    holder.release(); // owned by the eventual terminal callback now
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
        // ENOENT means the multishot recv already terminated on its own
        // (e.g. the peer disconnected) and its completion is already
        // queued, uncancellable -- not an error, just too late; see
        // _arm_recv()'s comment for how the eventual callback copes.
        if (res < 0 && res != -ENOENT) {
            rawstd_error("Failed to cancel event: %s\n", strerror(-res));
        }
    }
    close(_fd);
}

ssize_t Session::_recv(
    const iovec* iov, unsigned int niov, size_t result, int error, void* data
) noexcept {
    auto* weak = static_cast<std::weak_ptr<Session>*>(data);
    // Any non-zero error (not just ECANCELED) terminates this multishot
    // registration -- this is the one and only callback still holding
    // `weak` alive, so it's this callback's job to free it.
    std::unique_ptr<std::weak_ptr<Session>> owner(error ? weak : nullptr);

    std::shared_ptr<Session> session = weak->lock();
    if (session == nullptr) {
        // The Session is already gone -- its terminal completion was
        // already queued, uncancellable, by the time it was destroyed
        // (see ~Session()).
        return 0;
    }
    if (error == ECANCELED) {
        return 0;
    }
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
    case RAWSTOR_CMD_META:
    case RAWSTOR_CMD_LOCATION_INFO:
    case RAWSTOR_CMD_FLUSH:
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

        // 64MB limit -- reject before committing to receive this many
        // bytes of payload off the wire at all, rather than after
        // already reading the whole (possibly much larger) thing in
        // full just to then reject it in _write().
        if (_request_body.io.len > (1ULL << 26)) {
            rawstd_error(
                "fd %d: WRITE len too large: %u\n", _fd, _request_body.io.len
            );

            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        }

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

    case RAWSTOR_CMD_META:
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

        _meta(_request_head, _request_body.basic);

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

    // Always keeps reading -- see _write()'s own use of
    // write_throttle_limit() to decide whether *this* request gets
    // dispatched to storage now or queued for later, instead of pausing
    // the recv itself. (An earlier version paused recv here instead, by
    // canceling it: unreliable in practice -- re-arming it once a slot
    // freed up wouldn't pick up data the kernel had already buffered
    // while it was paused, stalling the session forever.)
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
        _send_response(RAWSTOR_CMD_LIST, head.cid, result, 0);
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
        _send_response(RAWSTOR_CMD_LIST, head.cid, data->size(), 0, data);
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

    auto ctx = std::make_unique<OpCtx>(
        OpCtx{weak_from_this(), RAWSTOR_CMD_ALLOCATE, head.cid}
    );

    int res = rawstor_object_create_async(
        _queue, rawstd::URI::uris(targets).c_str(), &spec, _op_complete,
        ctx.get()
    );
    if (res < 0) {
        _send_response(RAWSTOR_CMD_ALLOCATE, head.cid, res, 0);
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
        OpCtx{weak_from_this(), RAWSTOR_CMD_RELEASE, head.cid}
    );

    int res = rawstor_object_remove_async(
        _queue, rawstd::URI::uris(targets).c_str(), _op_complete, ctx.get()
    );
    if (res < 0) {
        _send_response(RAWSTOR_CMD_RELEASE, head.cid, res, 0);
        return;
    }

    ctx.release();
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
        _send_response(RAWSTOR_CMD_SPEC, head.cid, result, 0);
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(sizeof(spec));
    memcpy(data->data(), &spec, sizeof(spec));

    _send_response(RAWSTOR_CMD_SPEC, head.cid, data->size(), 0, data);
}

void Session::_info(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody&
) {
    RawstorLocationInfo info{};
    int result = rawstor_location_info(
        rawstd::URI::uris(_server.locations()).c_str(), &info
    );
    if (result < 0) {
        _send_response(RAWSTOR_CMD_LOCATION_INFO, head.cid, result, 0);
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(sizeof(info));
    memcpy(data->data(), &info, sizeof(info));

    _send_response(RAWSTOR_CMD_LOCATION_INFO, head.cid, data->size(), 0, data);
}

int Session::_op_complete(int result, void* data) noexcept {
    std::unique_ptr<OpCtx> ctx(static_cast<OpCtx*>(data));

    std::shared_ptr<Session> session = ctx->session.lock();
    if (!session) {
        return 0;
    }

    try {
        session->_send_response(ctx->cmd, ctx->cid, result, 0);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

int Session::_open_complete(
    RawstorObject* object, int result, void* data
) noexcept {
    std::unique_ptr<OpCtx> ctx(static_cast<OpCtx*>(data));

    std::shared_ptr<Session> session = ctx->session.lock();
    if (!session) {
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

    session->_open_pending = false;

    if (result == 0) {
        session->_object = object;
    }

    try {
        session->_send_response(ctx->cmd, ctx->cid, result, 0);
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

void Session::_set_object(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    if (_open_pending) {
        _send_response(RAWSTOR_CMD_SET_OBJECT, head.cid, -EBUSY, 0);
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

    auto ctx = std::make_unique<OpCtx>(
        OpCtx{weak_from_this(), RAWSTOR_CMD_SET_OBJECT, head.cid}
    );

    int res = rawstor_object_open_async(
        _queue, rawstd::URI::uris(targets).c_str(), _open_complete, ctx.get()
    );
    if (res < 0) {
        _send_response(RAWSTOR_CMD_SET_OBJECT, head.cid, res, 0);
        return;
    }

    _open_pending = true;
    ctx.release();
}

void Session::_read(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body
) {
    if (_object == nullptr) {
        _send_response(RAWSTOR_CMD_READ, head.cid, -EBADF, 0);
        return;
    }

    // 64MB limit
    if (body.len > (1ULL << 26)) {
        _send_response(RAWSTOR_CMD_READ, head.cid, -EINVAL, 0);
        return;
    }

    auto data = std::make_shared<std::vector<unsigned char>>(body.len);

    auto cb = std::make_unique<Callback>(
        [weak = weak_from_this(), cid = head.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            std::shared_ptr<Session> session = weak.lock();
            if (session == nullptr) {
                return;
            }
            try {
                session->_send_response(
                    RAWSTOR_CMD_READ, cid,
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
        _send_response(RAWSTOR_CMD_READ, head.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_write(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody& body,
    const iovec* iov, unsigned int niov, size_t size
) {
    if (_object == nullptr) {
        _send_response(RAWSTOR_CMD_WRITE, head.cid, -EBADF, 0);
        return;
    }

    bool throttled = _writes_in_flight >= _server.write_throttle_limit();

    if (throttled &&
        _pending_writes_bytes + size > _server.write_backlog_capacity()) {
        // Recv keeps running regardless (see _recv_data()), so nothing
        // else caps how much an already-throttled session could pile into
        // _pending_writes -- reject outright, before even copying the
        // payload out, once queuing it would push the backlog over the
        // cap, rather than let payload copies grow without bound while
        // storage catches up.
        _send_response(RAWSTOR_CMD_WRITE, head.cid, -EBUSY, 0);
        return;
    }

    // Hash iov directly -- no need to pay for the copy below at all if the
    // write is about to be rejected anyway.
    uint64_t hash;
    int hash_res = rawstd_hash_vector(iov, niov, &hash);
    if (hash_res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-hash_res);
    }

    if (hash != body.hash) {
        rawstd_error(
            "Hash mismatch: %llx != %llx\n",
            static_cast<unsigned long long>(hash),
            static_cast<unsigned long long>(body.hash)
        );
        _send_response(RAWSTOR_CMD_WRITE, head.cid, -EIO, 0);
        return;
    }

    // iov points into the recv buffer ring's own memory -- it's only
    // valid for the duration of this call, so the payload has to be
    // copied out now regardless of whether this write is about to be
    // dispatched or queued for later.
    auto data = std::make_shared<std::vector<unsigned char>>(size);
    rawstd_iovec_to_buf(iov, niov, 0, data->data(), size);

    if (throttled) {
        // Capping dispatch, not intake, is what keeps a backing store
        // slower than the incoming write rate from piling up an unbounded
        // number of concurrent pwrite()s at once; the backlog check above
        // is what keeps deferring writes like this one safe to do at all.
        _pending_writes_bytes += size;
        _pending_writes.push_back(
            {.head = head,
             .offset = body.offset,
             .sync = body.sync != 0,
             .data = data}
        );
        return;
    }

    _dispatch_write(head, body.offset, body.sync != 0, data);
}

void Session::_dispatch_write(
    const RawstorOSTFrameHead& head, uint64_t offset, bool sync,
    const std::shared_ptr<std::vector<unsigned char>>& data
) {
    auto cb = std::make_unique<Callback>(
        [weak = weak_from_this(), cid = head.cid,
         data](RawstorObject*, size_t, size_t result, int error) {
            std::shared_ptr<Session> session = weak.lock();
            if (session == nullptr) {
                return;
            }
            --session->_writes_in_flight;
            session->_dispatch_next_pending_write();
            try {
                session->_send_response(
                    RAWSTOR_CMD_WRITE, cid,
                    error ? -error : static_cast<int32_t>(result),
                    error ? 0 : rawstd_hash_scalar(data->data(), data->size())
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_pwrite(
        _object, data->data(), data->size(), offset, sync, callback, cb.get()
    );
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        _send_response(RAWSTOR_CMD_WRITE, head.cid, res, 0);
    } else {
        ++_writes_in_flight;
        cb.release();
    }
}

void Session::_dispatch_next_pending_write() {
    if (_pending_writes.empty() ||
        _writes_in_flight >= _server.write_throttle_limit()) {
        return;
    }

    PendingWrite next = std::move(_pending_writes.front());
    _pending_writes.pop_front();
    _pending_writes_bytes -= next.data->size();
    _dispatch_write(next.head, next.offset, next.sync, next.data);
}

void Session::_flush(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody&
) {
    if (_object == nullptr) {
        _send_response(RAWSTOR_CMD_FLUSH, head.cid, -EBADF, 0);
        return;
    }

    auto cb = std::make_unique<Callback>(
        [weak = weak_from_this(),
         cid = head.cid](RawstorObject*, size_t, size_t, int error) {
            std::shared_ptr<Session> session = weak.lock();
            if (session == nullptr) {
                return;
            }
            try {
                session->_send_response(
                    RAWSTOR_CMD_FLUSH, cid, error ? -error : 0, 0
                );
            } catch (const std::exception& e) {
                rawstd_error("%s\n", e.what());
            }
        }
    );

    int res = rawstor_object_flush(_object, callback, cb.get());
    if (res < 0) {
        rawstd_warning("%s\n", strerror(-res));
        _send_response(RAWSTOR_CMD_FLUSH, head.cid, res, 0);
    } else {
        cb.release();
    }
}

void Session::_discard(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameIOBody&
) {
    _send_response(RAWSTOR_CMD_DISCARD, head.cid, -ENOSYS, 0);
}

int Session::_meta_complete(int result, void* data) noexcept {
    std::unique_ptr<MetaCtx> ctx(static_cast<MetaCtx*>(data));

    std::shared_ptr<Session> session = ctx->session.lock();
    if (!session) {
        return 0;
    }

    try {
        /* Error responses carry no metadata payload. */
        if (result < 0) {
            session->_send_response(RAWSTOR_CMD_META, ctx->cid, result, 0);
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

        session->_send_response(
            RAWSTOR_CMD_META, ctx->cid, payload->size(),
            rawstd_hash_scalar(payload->data(), payload->size()), payload
        );
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
    }

    return 0;
}

void Session::_meta(
    const RawstorOSTFrameHead& head, const RawstorOSTFrameBasicBody& body
) {
    RawstdUUID uuid;
    memcpy(uuid.bytes, body.obj_id, sizeof(body.obj_id));

    std::vector<rawstd::URI> targets = _targets(uuid);

    auto ctx = std::make_unique<MetaCtx>();
    ctx->session = weak_from_this();
    ctx->cid = head.cid;
    memcpy(ctx->obj_id, body.obj_id, sizeof(ctx->obj_id));

    int res = rawstor_object_meta_async(
        _queue, rawstd::URI::uris(targets).c_str(), &ctx->meta, _meta_complete,
        ctx.get()
    );
    if (res < 0) {
        _meta_complete(res, ctx.release());
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
        OpCtx{weak_from_this(), RAWSTOR_CMD_SET_STATE, head.cid}
    );

    int res = rawstor_object_set_state_async(
        _queue, rawstd::URI::uris(targets).c_str(), &meta, _op_complete,
        ctx.get()
    );
    if (res < 0) {
        _send_response(RAWSTOR_CMD_SET_STATE, head.cid, res, 0);
        return;
    }

    ctx.release();
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

    auto cb = std::make_unique<IOCallback>([weak = weak_from_this(),
                                            server = &_server, fd = _fd,
                                            response](size_t, int) {
        /*
         * The session may already be gone, in which case fd is closed
         * (and possibly reused) and there is nothing left to tear down.
         */
        if (weak.expired()) {
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

void Session::_send_response(
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
        std::make_unique<IOCallback>([fd = _fd, &server = _server,
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
        _queue, _fd, response.get(), sizeof(*response), RAWSTD_MSG_NOSIGNAL,
        io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

void Session::_send_response(
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
        .msg_iovlen = static_cast<decltype(msghdr::msg_iovlen)>(iov->size()),
        .msg_control = nullptr,
        .msg_controllen = 0,
        .msg_flags = 0,
    });

    auto cb = std::make_unique<IOCallback>([fd = _fd, &server = _server, data,
                                            response, iov,
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
        _queue, _fd, msg.get(), RAWSTD_MSG_NOSIGNAL, io_callback, cb.get()
    );
    if (res < 0) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }

    cb.release();
}

} // namespace ostbackend
} // namespace rawstor
