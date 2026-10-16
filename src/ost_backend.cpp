#include "ost_backend.hpp"
#include "wire_backend_op.hpp"

#include <rawio/awaitable.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/socket.h>

#include <cinttypes>
#include <utility>

#define IOVEC_SIZE 256

namespace {

int validate_hash(uint64_t hash, uint64_t expected) noexcept {
    if (hash == expected) {
        return 0;
    }

    rawstd_error(
        "Hash mismatch: %llx != %llx\n", (unsigned long long)hash,
        (unsigned long long)expected
    );
    return EPROTO;
}

uint64_t hash(const void* buf, size_t size) {
    return rawstd_hash_scalar(buf, size);
}

uint64_t hash(const iovec* iov, unsigned int niov) {
    uint64_t ret;
    int res = rawstd_hash_vector(iov, niov, &ret);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}

} // namespace

namespace rawstor {
namespace ost {

using wire::BackendOp;
using wire::validate_cmd;
using wire::validate_response;
using wire::validate_result;

rawstd::Task<void> Backend::_connect() {
    return _wire_connect();
}

rawstd::Task<void> Backend::close() {
    return _wire_close();
}

rawstd::Task<void> Backend::list_chunks(
    RawstdUUID id, unsigned int limit, std::vector<ChunkGroup>& chunks,
    RawstdUUID& token, RawstdUUID version_id
) {
    return _wire_list_chunks(id, limit, chunks, token, version_id);
}

rawstd::Task<void> Backend::create(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t index,
    const RawstorObjectSpec& sp, RawstorMemberRole member_role
) {
    return _wire_create(idempotency_key, id, index, sp, member_role);
}

rawstd::Task<void> Backend::remove(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t index
) {
    return _wire_remove(idempotency_key, id, index);
}

rawstd::Task<void> Backend::remove_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t index,
    const RawstdUUID& version_id
) {
    return _wire_remove_version(idempotency_key, id, index, version_id);
}

rawstd::Task<std::vector<RawstdUUID>>
Backend::list_versions(const RawstdUUID& id, uint64_t index) {
    return _wire_list_versions(id, index);
}

rawstd::Task<std::vector<RawstorObjectMeta>> Backend::meta(
    const RawstdUUID& id, uint64_t index, const RawstdUUID& version_id
) {
    return _wire_meta(id, index, version_id);
}

rawstd::Task<std::vector<rawstd::URI>> Backend::resolve_locations(
    const RawstdUUID& id, uint64_t index, const RawstdUUID& version_id
) {
    return _wire_resolve_locations(id, index, version_id);
}

rawstd::Task<void> Backend::leave() {
    return _wire_leave();
}

rawstd::Task<bool> Backend::sync_prepare(
    const RawstdUUID& id, uint64_t index, const RawstorObjectBallot& ballot,
    bool proposed, RawstorObjectMeta& meta
) {
    return _wire_sync_prepare(id, index, ballot, proposed, meta);
}

rawstd::Task<bool> Backend::sync_accept(
    const RawstdUUID& id, uint64_t index, uint8_t member_index,
    const RawstorObjectBallot& ballot, const RawstorObjectBallot& next,
    const RawstorObjectConfig& config, bool proposed, RawstorObjectMeta& meta
) {
    return _wire_sync_accept(
        id, index, member_index, ballot, next, config, proposed, meta
    );
}

rawstd::Task<void>
Backend::set_object(const RawstdUUID& id, uint64_t index, int flags) {
    return _wire_set_object(id, index, flags);
}

rawstd::Task<void> Backend::set_version(
    const RawstdUUID& object_id, uint64_t index, const RawstdUUID& version_id
) {
    return _wire_set_version(object_id, index, version_id);
}

rawstd::Task<void> Backend::create_version(
    const RawstdUUID& idempotency_key, const RawstdUUID& id, uint64_t index,
    const RawstdUUID& version_id
) {
    return _wire_create_version(idempotency_key, id, index, version_id);
}

class BackendOpRead final : public BackendOp {
private:
    void* _buf;
    size_t _size;
    RawstorFrameIO _request;

    uint64_t _hash;

public:
    BackendOpRead(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        void* buf, size_t size, uint64_t offset,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "pread", size, offset),
        _buf(buf),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .payload =
                {
                    .offset = (uint64_t)offset,
                    .hash = 0,
                    .epoch = 0,
                    .len = (uint32_t)_size,
                    .flags = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t
    response_head_cb(const RawstorFrameResponse* response, int error) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_READ);
        }

        if (!error && response->body.res > 0) {
            // Trust the server's own reported byte count for how much
            // body follows, not our own originally-requested _size.
            _hash = response->body.hash;
            return static_cast<size_t>(response->body.res);
        }

        // No body follows either way: a real error, or a genuine
        // zero-byte read (response->body.res == 0, nothing to send).
        _dispatch(0, error);
        return 0;
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result
    ) override {
        int error = validate_hash(hash(iov, niov), _hash);
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (result) {
            rawstd_iovec_to_buf(iov, niov, 0, _buf, result);
        }

        _dispatch(result, error);
    }
};

class BackendOpReadV final : public BackendOp {
private:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;
    RawstorFrameIO _request;

    uint64_t _hash;

public:
    BackendOpReadV(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        const rawstd::TraceEvent& trace_event
    ) :
        BackendOp(backend, cid, trace_event, "preadv", size, offset),
        _iov(iov),
        _niov(niov),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .payload =
                {
                    .offset = (uint64_t)offset,
                    .hash = 0,
                    .epoch = 0,
                    .len = (uint32_t)_size,
                    .flags = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t
    response_head_cb(const RawstorFrameResponse* response, int error) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_READ);
        }

        if (!error && response->body.res > 0) {
            // Trust the server's own reported byte count for how much
            // body follows, not our own originally-requested _size.
            _hash = response->body.hash;
            return static_cast<size_t>(response->body.res);
        }

        // No body follows either way: a real error, or a genuine
        // zero-byte read (response->body.res == 0, nothing to send).
        _dispatch(0, error);
        return 0;
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result
    ) override {
        int error = validate_hash(hash(iov, niov), _hash);
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (result) {
            rawstd_iovec_to_iovec(iov, niov, 0, _iov, _niov);
        }

        _dispatch(result, error);
    }
};

class BackendOpWrite final : public BackendOp {
private:
    std::vector<iovec> _iov;
    RawstorFrameIO _request;
    msghdr _msg;

public:
    BackendOpWrite(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        const void* buf, size_t size, uint64_t offset, bool sync,
        const rawstd::TraceEvent& trace_event, uint64_t epoch, bool resync
    ) :
        BackendOp(backend, cid, trace_event, "pwrite", size, offset),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .payload = {
                .offset = (uint64_t)offset,
                .hash = hash(buf, size),
                .epoch = epoch,
                .len = (uint32_t)size,
                .flags = static_cast<uint8_t>(
                    (sync ? RAWSTOR_FLAG_SYNC : 0) |
                    (resync ? RAWSTOR_FLAG_RESYNC : 0)
                ),
            },
        }) {
        _iov.reserve(2);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        _iov.push_back({
            .iov_base = const_cast<void*>(buf),
            .iov_len = size,
        });
        _msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov.data(),
            .msg_iovlen = static_cast<decltype(_msg.msg_iovlen)>(_iov.size()),
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    }

    const msghdr* request_msg() const noexcept { return &_msg; }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.payload.len;
    }

    size_t
    response_head_cb(const RawstorFrameResponse* response, int error) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        // A write response never carries a body, regardless of error.
        return 0;
    }
};

class BackendOpWriteV final : public BackendOp {
private:
    RawstorFrameIO _request;
    std::vector<iovec> _iov;
    msghdr _msg;

public:
    BackendOpWriteV(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
        bool sync, const rawstd::TraceEvent& trace_event, uint64_t epoch
    ) :
        BackendOp(backend, cid, trace_event, "pwritev", size, offset),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .payload = {
                .offset = (uint64_t)offset,
                .hash = hash(iov, niov),
                .epoch = epoch,
                .len = (uint32_t)size,
                .flags = static_cast<uint8_t>(sync ? RAWSTOR_FLAG_SYNC : 0),
            },
        }) {
        _iov.reserve(1 + niov);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        for (unsigned int i = 0; i < niov; ++i) {
            _iov.push_back(iov[i]);
        }
        _msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov.data(),
            .msg_iovlen = static_cast<decltype(_msg.msg_iovlen)>(_iov.size()),
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    }

    const msghdr* request_msg() const noexcept { return &_msg; }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.payload.len;
    }

    size_t
    response_head_cb(const RawstorFrameResponse* response, int error) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        // A write response never carries a body, regardless of error.
        return 0;
    }
};

// Shared by BackendOpDiscard/BackendOpWriteZeroes below: both carry an
// offset+len request (RawstorFrameIO, same shape as BackendOpRead's,
// minus any payload) and a response that never carries a body -- same
// terminal shape as BackendOpWrite's own response_head_cb().
class BackendOpNoPayloadIO : public BackendOp {
protected:
    RawstorCommandType _cmd;
    RawstorFrameIO _request;

public:
    BackendOpNoPayloadIO(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        RawstorCommandType cmd, const char* op_name, size_t size,
        uint64_t offset, uint8_t flags, const rawstd::TraceEvent& trace_event,
        uint64_t epoch
    ) :
        BackendOp(backend, cid, trace_event, op_name, size, offset),
        _cmd(cmd),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = cmd,
                    .cid = cid,
                },
            .payload = {
                .offset = (uint64_t)offset,
                .hash = 0,
                .epoch = epoch,
                .len = (uint32_t)size,
                .flags = flags,
            },
        }) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t
    response_head_cb(const RawstorFrameResponse* response, int error) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, _cmd);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        // Neither a discard nor a write-zeroes response ever carries a
        // body, regardless of error.
        return 0;
    }
};

class BackendOpDiscard final : public BackendOpNoPayloadIO {
public:
    BackendOpDiscard(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        size_t size, uint64_t offset, const rawstd::TraceEvent& trace_event,
        uint64_t epoch
    ) :
        BackendOpNoPayloadIO(
            backend, cid, RAWSTOR_CMD_DISCARD, "discard", size, offset, 0,
            trace_event, epoch
        ) {}
};

class BackendOpWriteZeroes final : public BackendOpNoPayloadIO {
public:
    BackendOpWriteZeroes(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        size_t size, uint64_t offset, bool unmap, bool sync,
        const rawstd::TraceEvent& trace_event, uint64_t epoch, bool resync
    ) :
        BackendOpNoPayloadIO(
            backend, cid, RAWSTOR_CMD_WRITE_ZEROES, "write_zeroes", size,
            offset,
            (unmap ? RAWSTOR_FLAG_UNMAP : 0) | (sync ? RAWSTOR_FLAG_SYNC : 0) |
                (resync ? RAWSTOR_FLAG_RESYNC : 0),
            trace_event, epoch
        ) {}
};

class BackendOpFlush final : public BackendOp {
private:
    RawstorFrameBasic _request;

public:
    BackendOpFlush(
        const std::shared_ptr<rawstor::wire::Backend>& backend, uint16_t cid,
        const rawstd::TraceEvent& trace_event, uint64_t epoch
    ) :
        BackendOp(backend, cid, trace_event, "flush", 0, 0),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_FLUSH,
                    .cid = cid,
                },
            .payload = {
                .object_id = {},
                .chunk_index = 0,
                .version_id = {},
                .val = epoch,
            },
        }) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    size_t
    response_head_cb(const RawstorFrameResponse* response, int error) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_FLUSH);
        }

        _dispatch(0, error);

        // A flush response never carries a body, regardless of error.
        return 0;
    }
};

// SET_SYNC_STATE's request carries the full RawstorFrameMetaPayload (not
// just object_id/chunk_index/val like BackendOpBasic below), so it needs its
// own request shape -- the response is otherwise the same no-payload
// acknowledgement as BackendOpFlush above.
rawstd::Task<size_t> Backend::pread(void* buf, size_t size, uint64_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %" PRIu64 "\n", fd(), size, offset
    );

    std::shared_ptr<BackendOpRead> op = std::make_shared<BackendOpRead>(
        std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(), buf,
        size, offset, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t>
Backend::preadv(iovec* iov, unsigned int niov, size_t size, uint64_t offset) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %" PRIu64 "\n", fd(), size, offset
    );

    std::shared_ptr<BackendOpReadV> op = std::make_shared<BackendOpReadV>(
        std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(), iov,
        niov, size, offset, trace_event
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t> Backend::pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
) {
    return _pwrite(buf, size, offset, sync, epoch, false);
}

rawstd::Task<size_t> Backend::resync_pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch
) {
    return _pwrite(buf, size, offset, sync, epoch, true);
}

rawstd::Task<size_t> Backend::_pwrite(
    const void* buf, size_t size, uint64_t offset, bool sync, uint64_t epoch,
    bool resync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %" PRIu64 ", sync = %d\n", fd(),
        size, offset, sync
    );

    std::shared_ptr<BackendOpWrite> op = std::make_shared<BackendOpWrite>(
        std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(), buf,
        size, offset, sync, trace_event, epoch, resync
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.sendmsg(
            fd(), op->request_msg(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t> Backend::pwritev(
    const iovec* iov, unsigned int niov, size_t size, uint64_t offset,
    bool sync, uint64_t epoch
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %" PRIu64 ", sync = %d\n", fd(),
        size, offset, sync
    );

    std::shared_ptr<BackendOpWriteV> op = std::make_shared<BackendOpWriteV>(
        std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(), iov,
        niov, size, offset, sync, trace_event, epoch
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.sendmsg(
            fd(), op->request_msg(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t>
Backend::discard(size_t size, uint64_t offset, uint64_t epoch) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %" PRIu64 "\n", fd(), size, offset
    );

    std::shared_ptr<BackendOpDiscard> op = std::make_shared<BackendOpDiscard>(
        std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(),
        size, offset, trace_event, epoch
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<size_t> Backend::write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
) {
    return _write_zeroes(size, offset, unmap, sync, epoch, false);
}

rawstd::Task<size_t> Backend::resync_write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch
) {
    return _write_zeroes(size, offset, unmap, sync, epoch, true);
}

rawstd::Task<size_t> Backend::_write_zeroes(
    size_t size, uint64_t offset, bool unmap, bool sync, uint64_t epoch,
    bool resync
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's',
        "fd = %d, size = %zu, offset = %" PRIu64 ", unmap = %d, sync = %d\n",
        fd(), size, offset, unmap, sync
    );

    std::shared_ptr<BackendOpWriteZeroes> op =
        std::make_shared<BackendOpWriteZeroes>(
            std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(),
            size, offset, unmap, sync, trace_event, epoch, resync
        );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_return co_await *op;
}

rawstd::Task<void> Backend::flush(uint64_t epoch) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('s', "fd = %d\n", fd());

    std::shared_ptr<BackendOpFlush> op = std::make_shared<BackendOpFlush>(
        std::static_pointer_cast<Backend>(shared_from_this()), _next_cid(),
        trace_event, epoch
    );
    _add_op(op);

    try {
        size_t result = co_await _queue.send(
            fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL
        );
        RAWSTD_TRACE_EVENT_MESSAGE(
            trace_event, "%zu of %zu\n", result, op->request_size()
        );
        op->request_cb(validate_result(op->request_size(), result));
    } catch (const std::system_error& e) {
        op->request_cb(e.code().value());
    }

    co_await *op;
}

} // namespace ost
} // namespace rawstor
