#include "ost_session.hpp"

#include "object.hpp"
#include "opts.h"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uuid.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <arpa/inet.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256

/* The wire format hardcodes the history length; keep it in sync. */
static_assert(
    sizeof(RawstorOSTFrameMetaBody::sync_id_history) ==
    sizeof(RawstorObjectMeta::sync_id_history)
);

namespace {

class SessionOp;

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EAGAIN;
}

/*
 * A failed magic check means the stream framing is lost: the connection
 * cannot be used anymore. A negative res is a server-side error for one
 * operation: the real errno is propagated and the stream stays usable
 * (error responses carry no payload).
 */
int validate_frame(int fd, const RawstorOSTFrameResponse* response) noexcept {
    assert(response != nullptr);

    if (response->head.magic != RAWSTOR_MAGIC) {
        rawstd_error(
            "fd %d: Unexpected magic number: %x != %x\n", fd,
            response->head.magic, RAWSTOR_MAGIC
        );
        return EPROTO;
    }

    return 0;
}

/*
 * Every response carries the payload length: a success response must
 * announce exactly the payload the command expects, an error response
 * carries none. Any other length means the stream framing is lost.
 */
int validate_len(int fd, uint32_t len, uint32_t expected) noexcept {
    if (len == expected) {
        return 0;
    }

    rawstd_error(
        "fd %d: Unexpected payload length: %u != %u\n", fd, len, expected
    );
    return EPROTO;
}

int validate_response(
    int fd, const RawstorOSTFrameResponse* response, uint32_t expected_len
) noexcept {
    int error = validate_frame(fd, response);
    if (error) {
        return error;
    }

    if (response->body.res < 0) {
        error = validate_len(fd, response->body.len, 0);
        if (error) {
            return error;
        }
        rawstd_error(
            "fd %d: Server error: %s\n", fd, strerror(-response->body.res)
        );
        return -response->body.res;
    }

    return validate_len(fd, response->body.len, expected_len);
}

int validate_cmd(
    int fd, RawstorOSTCommandType cmd, RawstorOSTCommandType expected
) noexcept {
    if (cmd == expected) {
        return 0;
    }

    rawstd_error("fd %d: Unexpected command: %d\n", fd, cmd);
    return EPROTO;
}

int validate_hash(int fd, uint64_t hash, uint64_t expected) noexcept {
    if (hash == expected) {
        return 0;
    }

    rawstd_error(
        "fd %d: Hash mismatch: %llx != %llx\n", fd, (unsigned long long)hash,
        (unsigned long long)expected
    );
    return EPROTO;
}

/*
 * Shared response-head handling for in-flight operations: returns 0 when
 * the response reports success, otherwise the errno to dispatch. *fatal is
 * set when the stream framing is lost (transport failure, bad magic,
 * command mixup, payload length mismatch): the receive loop must stop. A
 * server-side error (res < 0) is not fatal: error responses carry no
 * payload, so the stream stays framed.
 */
int classify_response(
    int fd, const RawstorOSTFrameResponse* response, int error,
    RawstorOSTCommandType expected, uint32_t expected_len, bool* fatal
) noexcept {
    *fatal = true;

    if (error) {
        return error;
    }

    error = validate_frame(fd, response);
    if (error) {
        return error;
    }

    error = validate_cmd(fd, response->head.cmd, expected);
    if (error) {
        return error;
    }

    if (response->body.res < 0) {
        error = validate_len(fd, response->body.len, 0);
        if (error) {
            return error;
        }
        *fatal = false;
        rawstd_error(
            "fd %d: Server error: %s\n", fd, strerror(-response->body.res)
        );
        return -response->body.res;
    }

    error = validate_len(fd, response->body.len, expected_len);
    if (error) {
        return error;
    }

    *fatal = false;

    return 0;
}

} // namespace

namespace rawstor {
namespace ost {

class Context final : public std::enable_shared_from_this<Context> {
private:
    rawio::Queue& _queue;
    int _fd;
    std::unordered_map<uint16_t, std::shared_ptr<SessionOp>> _ops;
    RawIOEvent* _read_event;

    /*
     * Set once the receive loop terminates (peer closed the connection or
     * a protocol failure): responses can never arrive anymore, so new
     * operations must be refused instead of hanging forever.
     */
    bool _dead;

    void _fail_in_flight(int error, bool* next_head, size_t* next_size);

    SessionOp& _find_op(uint16_t cid) {
        auto it = _ops.find(cid);
        if (it == _ops.end()) {
            rawstd_error("Unexpected cid: %u\n", cid);
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }

        return *it->second.get();
    }

public:
    Context(rawio::Queue& queue, int fd) :
        _queue(queue),
        _fd(fd),
        _read_event(nullptr),
        _dead(false) {}

    void setup_recv();
    void teardown_recv() noexcept;

    int fd() const noexcept { return _fd; }

    bool dead() const noexcept { return _dead; }

    void register_op(const std::shared_ptr<SessionOp>& op);

    void unregister_op(uint16_t cid) { _ops.erase(cid); }
};

} // namespace ost
} // namespace rawstor

namespace {

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

class SessionOp {
private:
    uint16_t _cid;
    bool _in_flight;

protected:
    rawstd::TraceEvent _trace_event;
    std::shared_ptr<rawstor::ost::Context> _context;
    RawstorOSTFrameResponse _response;

    std::function<void(size_t, int)> _cb;

    inline void _dispatch(size_t result, int error) {
        _in_flight = false;
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight end");

        try {
            _cb(result, error);
        } catch (...) {
            _context->unregister_op(_cid);
            throw;
        }

        _context->unregister_op(_cid);
    }

public:
    SessionOp(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        _cid(cid),
        _in_flight(false),
        _trace_event(trace_event),
        _context(context),
        _cb(std::move(cb)) {}

    SessionOp(const SessionOp&) = delete;
    SessionOp(SessionOp&&) = delete;
    virtual ~SessionOp() = default;

    SessionOp& operator=(const SessionOp&) = delete;
    SessionOp& operator=(SessionOp&&) = delete;

    inline rawstor::ost::Context& context() noexcept { return *_context; }

    inline uint16_t cid() const noexcept { return _cid; }

    inline bool in_flight() const noexcept { return _in_flight; }

    virtual size_t request_size() const noexcept = 0;

    void request_cb(int error) {
        _in_flight = true;
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight begin");

        /*
         * The request may complete into the socket buffer after the
         * receive loop already terminated: no response will ever arrive.
         */
        if (!error && _context->dead()) {
            error = EPIPE;
        }

        if (error) {
            _dispatch(0, error);
        }
    }

    virtual void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) = 0;

    virtual void response_body_cb(const iovec*, unsigned int, size_t, int) {}
};

class SessionOpRead final : public SessionOp {
private:
    void* _buf;
    size_t _size;
    RawstorOSTFrameIO _request;

    uint64_t _hash;

public:
    SessionOpRead(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        void* buf, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _buf(buf),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .body =
                {
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)_size,
                    .hash = 0,
                    .sync = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_READ, (uint32_t)_size,
            &fatal
        );

        if (!error) {
            _hash = response->body.hash;
            *next_head = false;
            *next_size = _size;
        } else {
            _dispatch(0, error);
            *next_head = true;
            *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (!error) {
            error = validate_hash(_context->fd(), hash(iov, niov), _hash);
        }

        if (result) {
            rawstd_iovec_to_buf(iov, niov, 0, _buf, result);
        }

        _dispatch(result, error);
    }
};

class SessionOpReadV final : public SessionOp {
private:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;
    RawstorOSTFrameIO _request;

    uint64_t _hash;

public:
    SessionOpReadV(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
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
            .body =
                {
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)_size,
                    .hash = 0,
                    .sync = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_READ, (uint32_t)_size,
            &fatal
        );

        if (!error) {
            _hash = response->body.hash;
            *next_head = false;
            *next_size = _size;
        } else {
            _dispatch(0, error);
            *next_head = true;
            *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (!error) {
            error = validate_hash(_context->fd(), hash(iov, niov), _hash);
        }

        if (result) {
            rawstd_iovec_to_iovec(iov, niov, 0, _iov, _niov);
        }

        _dispatch(result, error);
    }
};

class SessionOpWrite final : public SessionOp {
private:
    std::vector<iovec> _iov;
    RawstorOSTFrameIO _request;

public:
    SessionOpWrite(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const void* buf, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .body = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash(buf, size),
                .sync = 0,
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
    }

    const iovec* request_iov() const noexcept { return _iov.data(); }

    unsigned int request_niov() const noexcept { return _iov.size(); }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.body.len;
    }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_WRITE, 0, &fatal
        );

        _dispatch(!error ? response->body.res : 0, error);

        *next_head = true;
        *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

class SessionOpWriteV final : public SessionOp {
private:
    RawstorOSTFrameIO _request;
    std::vector<iovec> _iov;

public:
    SessionOpWriteV(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .body = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash(iov, niov),
                .sync = 0,
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
    }

    const iovec* request_iov() const noexcept { return _iov.data(); }

    unsigned int request_niov() const noexcept { return _iov.size(); }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.body.len;
    }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_WRITE, 0, &fatal
        );

        _dispatch(!error ? response->body.res : 0, error);

        *next_head = true;
        *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

class SessionOpSpec final : public SessionOp {
private:
    RawstorOSTFrameBasic _request;
    RawstorObjectMeta* _out;

    uint64_t _hash;

public:
    SessionOpSpec(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const RawstdUUID& id, RawstorObjectMeta* out,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SPEC,
                    .cid = cid,
                },
            .body =
                {
                    .obj_id = {},
                    .offset = 0,
                    .val = 0,
                },
        }),
        _out(out),
        _hash(0) {
        memcpy(_request.body.obj_id, id.bytes, sizeof(_request.body.obj_id));
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_SPEC,
            sizeof(RawstorOSTFrameMetaBody), &fatal
        );

        if (!error) {
            _hash = response->body.hash;
            *next_head = false;
            *next_size = sizeof(RawstorOSTFrameMetaBody);
        } else {
            /* Error responses carry no metadata payload. */
            _dispatch(0, error);
            *next_head = true;
            *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        RawstorOSTFrameMetaBody body{};

        if (!error && result != sizeof(body)) {
            error = EPROTO;
        }

        if (!error) {
            rawstd_iovec_to_buf(iov, niov, 0, &body, sizeof(body));
            error =
                validate_hash(_context->fd(), hash(&body, sizeof(body)), _hash);
        }

        if (!error) {
            _out->size = body.size;
            _out->epoch = body.epoch;
            _out->sync_id = body.sync_id;
            memcpy(
                _out->sync_id_history, body.sync_id_history,
                sizeof(_out->sync_id_history)
            );
            _out->state = body.state;
            _out->member_kind = body.member_kind;
            _out->width = body.width;
            memcpy(_out->volume_id, body.volume_id, sizeof(_out->volume_id));
            _out->logical_index = body.logical_index;
            _out->chunk_size = body.chunk_size;
            _out->snap_version = body.snap_version;
        }

        _dispatch(0, error);
    }
};

class SessionOpSetState final : public SessionOp {
private:
    RawstorOSTFrameMeta _request;

public:
    SessionOpSetState(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const RawstdUUID& id, const RawstorObjectMeta& meta,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SET_STATE,
                    .cid = cid,
                },
            .body = {
                .obj_id = {},
                .size = meta.size,
                .epoch = meta.epoch,
                .sync_id = meta.sync_id,
                .sync_id_history = {},
                .state = meta.state,
                .member_kind = meta.member_kind,
                .width = meta.width,
                .reserved = 0,
                .volume_id = {},
                .logical_index = meta.logical_index,
                .chunk_size = meta.chunk_size,
                .snap_version = meta.snap_version,
            },
        }) {
        memcpy(_request.body.obj_id, id.bytes, sizeof(_request.body.obj_id));
        memcpy(
            _request.body.sync_id_history, meta.sync_id_history,
            sizeof(_request.body.sync_id_history)
        );
        memcpy(
            _request.body.volume_id, meta.volume_id,
            sizeof(_request.body.volume_id)
        );
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_SET_STATE, 0, &fatal
        );

        _dispatch(0, error);

        *next_head = true;
        *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

/*
 * A zero-payload basic command (SNAPSHOT, SNAP_REMOVE) dispatched through
 * the multishot receive context of an object-bound session.
 */
class SessionOpBasic final : public SessionOp {
private:
    RawstorOSTFrameBasic _request;

public:
    SessionOpBasic(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        RawstorOSTCommandType cmd, const RawstdUUID& id, uint64_t val,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = cmd,
                    .cid = cid,
                },
            .body =
                {
                    .obj_id = {},
                    .offset = 0,
                    .val = val,
                },
        }) {
        memcpy(_request.body.obj_id, id.bytes, sizeof(_request.body.obj_id));
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, _request.head.cmd, 0, &fatal
        );

        _dispatch(0, error);

        *next_head = true;
        *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

class SessionOpFlush final : public SessionOp {
private:
    RawstorOSTFrameIO _request;

public:
    SessionOpFlush(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_FLUSH,
                    .cid = cid,
                },
            .body = {
                .offset = 0,
                .len = 0,
                .hash = 0,
                .sync = 1,
            },
        }) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        bool fatal = false;
        error = classify_response(
            _context->fd(), response, error, RAWSTOR_CMD_FLUSH, 0, &fatal
        );

        _dispatch(0, error);

        *next_head = true;
        *next_size = fatal ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

} // namespace

namespace rawstor {
namespace ost {

void Context::_fail_in_flight(int error, bool* next_head, size_t* next_size) {
    _dead = true;

    if (!_ops.empty()) {
        std::vector<std::shared_ptr<SessionOp>> in_flight_ops;
        in_flight_ops.reserve(_ops.size());
        for (const auto& i : _ops) {
            if (i.second->in_flight()) {
                in_flight_ops.push_back(i.second);
            }
        }
        for (const auto& i : in_flight_ops) {
            i->response_head_cb(nullptr, error, next_head, next_size);
        }
    }
    *next_head = true;
    *next_size = 0;
}

void Context::setup_recv() {
    assert(_read_event == nullptr);

    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('m', "%s\n", "multishot recv");
    _read_event = _queue.recv_multishot(
        _fd, 1u << 17, 64 * 4, sizeof(RawstorOSTFrameResponse), 0,
        [context = shared_from_this(), fd = _fd, cid = 0, is_head = true,
         size = sizeof(RawstorOSTFrameResponse), trace_event](
            const iovec* iov, unsigned int niov, size_t result, int error
        ) mutable -> size_t {
            if (error == ECANCELED) {
                return 0;
            }

            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result, size, error
            );

            if (!error) {
                error = validate_result(fd, size, result);
            }

            if (!error) {
                try {
                    if (is_head) {
                        RawstorOSTFrameResponse response;
                        rawstd_iovec_to_buf(
                            iov, niov, 0, &response, sizeof(response)
                        );
                        cid = response.head.cid;
                        SessionOp& op = context->_find_op(cid);
                        op.response_head_cb(&response, 0, &is_head, &size);
                    } else {
                        SessionOp& op = context->_find_op(cid);
                        op.response_body_cb(iov, niov, result, error);
                        is_head = true;
                        size = sizeof(RawstorOSTFrameResponse);
                    }
                } catch (const std::system_error& e) {
                    error = e.code().value();
                    context->_read_event = nullptr;
                    context->_fail_in_flight(error, &is_head, &size);
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                } catch (const std::exception& e) {
                    rawstd_error("%s\n", e.what());
                    error = EPROTO;
                    context->_read_event = nullptr;
                    context->_fail_in_flight(error, &is_head, &size);
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                }
            }

            if (error) {
                /*
                 * A terminal error ends the multishot event: the queue
                 * releases it, so it must not be cancelled in
                 * teardown_recv() - the stale pointer could alias an event
                 * of another session by then.
                 */
                context->_read_event = nullptr;
                context->_fail_in_flight(error, &is_head, &size);
            }

            return size;
        }
    );
}

void Context::teardown_recv() noexcept {
    if (_read_event != nullptr) {
        try {
            _queue.cancel(_read_event);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel event: %s\n", e.what());
        }
        _read_event = nullptr;
    }

    _dead = true;

    /*
     * Registered operations hold the context and the context holds them:
     * abandoned operations (e.g. a detached read-repair cut short by the
     * object teardown) must be dropped here or the cycle leaks both.
     */
    _ops.clear();
}

void Context::register_op(const std::shared_ptr<SessionOp>& op) {
    _ops[op->cid()] = op;
}

Session::Session(rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(queue, location),
    _cid_counter(0),
    _handshaken(false) {
}

Session::~Session() {
    if (_context.get() != nullptr) {
        _context->teardown_recv();
    }
}

void Session::connect(std::function<void(int)>&& cb) {
    if (!location().path().str().empty() && location().path().str() != "/") {
        rawstd_error("Empty path expected: %s\n", location().str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    int res;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            res = rawstd_socket_set_snd_timeout(fd, so_sndtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            res = rawstd_socket_set_rcv_timeout(fd, so_rcvtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
        if (tcp_user_timeo != 0) {
            res = rawstd_socket_set_user_timeout(fd, tcp_user_timeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        /*
         * The address is kept alive by the callback capture: io_uring reads
         * it when the connect operation is executed, not when submitted.
         * The socket stays blocking, so SO_SNDTIMEO still bounds the
         * connect; io_uring runs it in a worker thread without stalling
         * the event loop.
         */
        auto servaddr = std::make_shared<sockaddr_in>();
        servaddr->sin_family = AF_INET;
        servaddr->sin_port = htons(location().port());

        res = inet_pton(
            AF_INET, location().hostname().c_str(), &servaddr->sin_addr
        );
        if (res == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        rawstd_info(
            "fd %d: Connecting to %s...\n", fd, location().str().c_str()
        );

        _queue.connect(
            fd, reinterpret_cast<const sockaddr*>(servaddr.get()),
            sizeof(*servaddr),
            [this, fd, servaddr, cb = std::move(cb)](int result) {
                if (result < 0) {
                    ::close(fd);
                    rawstd_info("fd %d: Closed\n", fd);
                    cb(-result);
                    return;
                }

                rawstd_info("fd %d: Connected\n", fd);

                try {
                    rawio::Queue::setup_fd(fd);
                } catch (const std::system_error& e) {
                    ::close(fd);
                    rawstd_info("fd %d: Closed\n", fd);
                    cb(e.code().value());
                    return;
                }

                set_fd(fd);
                cb(0);
            }
        );
    } catch (...) {
        ::close(fd);
        rawstd_info("fd %d: Closed\n", fd);
        throw;
    }
}

void Session::_basic(
    RawstorOSTCommandType cmd, const RawstdUUID& id, uint64_t val,
    std::function<void(int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "basic cmd %d\n", cmd);

    auto request =
        std::make_shared<RawstorOSTFrameBasic>((RawstorOSTFrameBasic){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = cmd,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = val,
            },
        });
    memcpy(request->body.obj_id, id.bytes, sizeof(request->body.obj_id));

    auto cb_sp = std::make_shared<std::function<void(int)>>(std::move(cb));

    _queue.write(
        fd(), request.get(), sizeof(*request),
        [q = &_queue, fd = fd(), cmd, request, cb_sp,
         trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameBasic), error
            );

            if (!error) {
                error =
                    validate_result(fd, sizeof(RawstorOSTFrameBasic), result);
            }

            if (error) {
                (*cb_sp)(error);
                return;
            }

            auto response = std::make_shared<RawstorOSTFrameResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(*response),
                    [fd, cmd, response, cb_sp,
                     trace_event](size_t result, int error) {
                        RAWSTD_TRACE_EVENT_MESSAGE(
                            trace_event, "%zu of %zu, error = %d\n", result,
                            sizeof(RawstorOSTFrameResponse), error
                        );

                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error) {
                            error = validate_response(fd, response.get(), 0);
                        }

                        if (!error) {
                            error = validate_cmd(fd, response->head.cmd, cmd);
                        }

                        (*cb_sp)(error);
                    }
                );
            } catch (const std::system_error& e) {
                (*cb_sp)(e.code().value());
            } catch (const std::bad_alloc& e) {
                (*cb_sp)(ENOMEM);
            }
        }
    );
}

void Session::_set_object_exchange(
    const RawstdUUID* id, std::function<void(int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "%s\n", "set_object handshake");

    auto request =
        std::make_shared<RawstorOSTFrameSetObject>((RawstorOSTFrameSetObject){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SET_OBJECT,
                    .cid = _cid_counter++,
                },
            .body = {
                .version = RAWSTOR_PROTOCOL_VERSION,
                .features = 0,
                .obj_id = {},
                .val = 0,
            },
        });
    if (id != nullptr) {
        memcpy(request->body.obj_id, id->bytes, sizeof(request->body.obj_id));
    }

    auto cb_sp = std::make_shared<std::function<void(int)>>(std::move(cb));

    _queue.write(
        fd(), request.get(), sizeof(*request),
        [this, q = &_queue, fd = fd(), request, cb_sp,
         trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameSetObject), error
            );

            if (!error) {
                error = validate_result(
                    fd, sizeof(RawstorOSTFrameSetObject), result
                );
            }

            if (error) {
                (*cb_sp)(error);
                return;
            }

            auto response = std::make_shared<RawstorOSTFrameResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(*response),
                    [this, q, fd, response, cb_sp,
                     trace_event](size_t result, int error) {
                        RAWSTD_TRACE_EVENT_MESSAGE(
                            trace_event, "%zu of %zu, error = %d\n", result,
                            sizeof(RawstorOSTFrameResponse), error
                        );

                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error) {
                            error = validate_response(
                                fd, response.get(),
                                sizeof(RawstorOSTFrameHelloBody)
                            );
                        }

                        if (!error) {
                            error = validate_cmd(
                                fd, response->head.cmd, RAWSTOR_CMD_SET_OBJECT
                            );
                        }

                        if (error) {
                            (*cb_sp)(error);
                            return;
                        }

                        auto hello =
                            std::make_shared<RawstorOSTFrameHelloBody>();

                        try {
                            q->read(
                                fd, hello.get(), sizeof(*hello),
                                [this, fd, response, hello,
                                 cb_sp](size_t result, int error) {
                                    if (!error) {
                                        error = validate_result(
                                            fd, sizeof(*hello), result
                                        );
                                    }

                                    if (!error) {
                                        error = validate_hash(
                                            fd,
                                            hash(hello.get(), sizeof(*hello)),
                                            response->body.hash
                                        );
                                    }

                                    if (!error &&
                                        hello->version !=
                                            RAWSTOR_PROTOCOL_VERSION) {
                                        rawstd_error(
                                            "fd %d: Unsupported server "
                                            "protocol version: %u != %u\n",
                                            fd, hello->version,
                                            RAWSTOR_PROTOCOL_VERSION
                                        );
                                        error = EPROTONOSUPPORT;
                                    }

                                    if (!error) {
                                        _handshaken = true;
                                    }

                                    (*cb_sp)(error);
                                }
                            );
                        } catch (const std::system_error& e) {
                            (*cb_sp)(e.code().value());
                        } catch (const std::bad_alloc& e) {
                            (*cb_sp)(ENOMEM);
                        }
                    }
                );
            } catch (const std::system_error& e) {
                (*cb_sp)(e.code().value());
            } catch (const std::bad_alloc& e) {
                (*cb_sp)(ENOMEM);
            }
        }
    );
}

void Session::_ensure_handshake(std::function<void(int)>&& cb) {
    if (_handshaken) {
        cb(0);
        return;
    }

    _set_object_exchange(nullptr, std::move(cb));
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& spec,
    std::function<void(int)>&& cb
) {
    _ensure_handshake([this, id, spec, cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        _allocate(id, spec, std::move(cb));
    });
}

/*
 * ALLOCATE: like _basic, but the request carries the full creation spec
 * including the placement identity the backend must record.
 */
void Session::_allocate(
    const RawstdUUID& id, const RawstorObjectSpec& spec,
    std::function<void(int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "%s\n", "allocate cmd");

    auto request =
        std::make_shared<RawstorOSTFrameAllocate>((RawstorOSTFrameAllocate){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_ALLOCATE,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .size = spec.size,
                .chunk_size = spec.chunk_size,
                .stripe_width = spec.stripe_width,
                .width = spec.width,
                .failure_domain = spec.failure_domain,
                .member_kind = spec.member_kind,
                .reserved = 0,
                .volume_id = {},
                .logical_index = spec.logical_index,
                .snap_version = spec.snap_version,
            },
        });
    memcpy(request->body.obj_id, id.bytes, sizeof(request->body.obj_id));
    memcpy(
        request->body.volume_id, spec.volume_id, sizeof(request->body.volume_id)
    );

    auto cb_sp = std::make_shared<std::function<void(int)>>(std::move(cb));

    _queue.write(
        fd(), request.get(), sizeof(*request),
        [q = &_queue, fd = fd(), request, cb_sp,
         trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameAllocate), error
            );

            if (!error) {
                error = validate_result(
                    fd, sizeof(RawstorOSTFrameAllocate), result
                );
            }

            if (error) {
                (*cb_sp)(error);
                return;
            }

            auto response = std::make_shared<RawstorOSTFrameResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(*response),
                    [fd, response, cb_sp,
                     trace_event](size_t result, int error) {
                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error) {
                            error = validate_response(fd, response.get(), 0);
                        }

                        if (!error) {
                            error = validate_cmd(
                                fd, response->head.cmd, RAWSTOR_CMD_ALLOCATE
                            );
                        }

                        (*cb_sp)(error);
                    }
                );
            } catch (const std::system_error& e) {
                (*cb_sp)(e.code().value());
            } catch (const std::bad_alloc& e) {
                (*cb_sp)(ENOMEM);
            }
        }
    );
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    _ensure_handshake([this, id, cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        _basic(RAWSTOR_CMD_RELEASE, id, 0, std::move(cb));
    });
}

/*
 * See meta(): an object-bound session dispatches through the multishot
 * receive context, an unbound one runs the plain pre-open exchange.
 */
void Session::_basic_or_op(
    RawstorOSTCommandType cmd, const RawstdUUID& id, uint64_t val,
    std::function<void(int)>&& cb
) {
    if (_context != nullptr) {
        rawstd::TraceEvent trace_event =
            RAWSTD_TRACE_EVENT('s', "basic cmd %d\n", cmd);

        std::shared_ptr<SessionOpBasic> op = std::make_shared<SessionOpBasic>(
            _context, _cid_counter++, cmd, id, val, trace_event,
            [cb = std::move(cb)](size_t, int error) { cb(error); }
        );
        _context->register_op(op);

        _queue.write(
            fd(), op->request_data(), op->request_size(),
            [op, trace_event](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "%zu of %zu, error = %d\n", result,
                    op->request_size(), error
                );

                if (!error) {
                    error = validate_result(
                        op->context().fd(), op->request_size(), result
                    );
                }

                op->request_cb(error);
            }
        );
        return;
    }

    _ensure_handshake([this, cmd, id, val,
                       cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        _basic(cmd, id, val, std::move(cb));
    });
}

void Session::snapshot(
    const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
) {
    _basic_or_op(RAWSTOR_CMD_SNAPSHOT, id, snap_id, std::move(cb));
}

void Session::snap_remove(
    const RawstdUUID& id, uint64_t snap_id, std::function<void(int)>&& cb
) {
    _basic_or_op(RAWSTOR_CMD_SNAP_REMOVE, id, snap_id, std::move(cb));
}

void Session::meta(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "%s\n", "spec cmd");

    /*
     * On an object-bound session the socket is owned by the multishot
     * receive context: the request must be dispatched as a regular
     * in-flight operation. The plain request/response exchange below is
     * only valid before set_object().
     */
    if (_context != nullptr) {
        auto out = std::make_shared<RawstorObjectMeta>();

        std::shared_ptr<SessionOpSpec> op = std::make_shared<SessionOpSpec>(
            _context, _cid_counter++, id, out.get(), trace_event,
            [out, cb = std::move(cb)](size_t, int error) { cb(*out, error); }
        );
        _context->register_op(op);

        _queue.write(
            fd(), op->request_data(), op->request_size(),
            [op, trace_event](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "%zu of %zu, error = %d\n", result,
                    op->request_size(), error
                );

                if (!error) {
                    error = validate_result(
                        op->context().fd(), op->request_size(), result
                    );
                }

                op->request_cb(error);
            }
        );
        return;
    }

    _ensure_handshake([this, id, cb = std::move(cb)](int error) mutable {
        if (error) {
            cb({}, error);
            return;
        }

        _meta_exchange(id, std::move(cb));
    });
}

void Session::_meta_exchange(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectMeta&, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "%s\n", "spec cmd");

    auto request =
        std::make_shared<RawstorOSTFrameBasic>((RawstorOSTFrameBasic){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SPEC,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = 0,
            },
        });
    memcpy(request->body.obj_id, id.bytes, sizeof(request->body.obj_id));

    auto cb_sp =
        std::make_shared<std::function<void(const RawstorObjectMeta&, int)>>(
            std::move(cb)
        );

    _queue.write(
        fd(), request.get(), sizeof(*request),
        [q = &_queue, fd = fd(), request, cb_sp,
         trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameBasic), error
            );

            if (!error) {
                error =
                    validate_result(fd, sizeof(RawstorOSTFrameBasic), result);
            }

            if (error) {
                (*cb_sp)({}, error);
                return;
            }

            /*
             * The response is read in two phases: the head+body first, the
             * metadata payload only on success. Error responses carry no
             * payload.
             */
            auto response = std::make_shared<RawstorOSTFrameSpecResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(RawstorOSTFrameResponse),
                    [q, fd, response, cb_sp,
                     trace_event](size_t result, int error) {
                        RAWSTD_TRACE_EVENT_MESSAGE(
                            trace_event, "%zu of %zu, error = %d\n", result,
                            sizeof(RawstorOSTFrameResponse), error
                        );

                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error) {
                            error = validate_response(
                                fd,
                                reinterpret_cast<RawstorOSTFrameResponse*>(
                                    response.get()
                                ),
                                sizeof(response->meta)
                            );
                        }

                        if (!error) {
                            error = validate_cmd(
                                fd, response->head.cmd, RAWSTOR_CMD_SPEC
                            );
                        }

                        if (error) {
                            (*cb_sp)({}, error);
                            return;
                        }

                        try {
                            q->read(
                                fd, &response->meta, sizeof(response->meta),
                                [fd, response, cb_sp,
                                 trace_event](size_t result, int error) {
                                    RAWSTD_TRACE_EVENT_MESSAGE(
                                        trace_event, "%zu of %zu, error = %d\n",
                                        result, sizeof(response->meta), error
                                    );

                                    if (!error) {
                                        error = validate_result(
                                            fd, sizeof(response->meta), result
                                        );
                                    }

                                    if (!error) {
                                        error = validate_hash(
                                            fd,
                                            hash(
                                                &response->meta,
                                                sizeof(response->meta)
                                            ),
                                            response->body.hash
                                        );
                                    }

                                    if (error) {
                                        (*cb_sp)({}, error);
                                        return;
                                    }

                                    RawstorObjectMeta meta{};
                                    meta.size = response->meta.size;
                                    meta.epoch = response->meta.epoch;
                                    meta.sync_id = response->meta.sync_id;
                                    memcpy(
                                        meta.sync_id_history,
                                        response->meta.sync_id_history,
                                        sizeof(meta.sync_id_history)
                                    );
                                    meta.state = response->meta.state;
                                    meta.member_kind =
                                        response->meta.member_kind;
                                    meta.width = response->meta.width;
                                    memcpy(
                                        meta.volume_id,
                                        response->meta.volume_id,
                                        sizeof(meta.volume_id)
                                    );
                                    meta.logical_index =
                                        response->meta.logical_index;
                                    meta.chunk_size = response->meta.chunk_size;
                                    meta.snap_version =
                                        response->meta.snap_version;

                                    (*cb_sp)(meta, 0);
                                }
                            );
                        } catch (const std::system_error& e) {
                            (*cb_sp)({}, e.code().value());
                        } catch (const std::bad_alloc& e) {
                            (*cb_sp)({}, ENOMEM);
                        }
                    }
                );
            } catch (const std::system_error& e) {
                (*cb_sp)({}, e.code().value());
            } catch (const std::bad_alloc& e) {
                (*cb_sp)({}, ENOMEM);
            }
        }
    );
}

void Session::set_state(
    const RawstdUUID& id, const RawstorObjectMeta& meta,
    std::function<void(int)>&& cb
) {
    /*
     * See meta(): an object-bound session dispatches through the multishot
     * receive context.
     */
    if (_context != nullptr) {
        rawstd::TraceEvent trace_event =
            RAWSTD_TRACE_EVENT('s', "%s\n", "set_state cmd");

        std::shared_ptr<SessionOpSetState> op =
            std::make_shared<SessionOpSetState>(
                _context, _cid_counter++, id, meta, trace_event,
                [cb = std::move(cb)](size_t, int error) { cb(error); }
            );
        _context->register_op(op);

        _queue.write(
            fd(), op->request_data(), op->request_size(),
            [op, trace_event](size_t result, int error) {
                RAWSTD_TRACE_EVENT_MESSAGE(
                    trace_event, "%zu of %zu, error = %d\n", result,
                    op->request_size(), error
                );

                if (!error) {
                    error = validate_result(
                        op->context().fd(), op->request_size(), result
                    );
                }

                op->request_cb(error);
            }
        );
        return;
    }

    _ensure_handshake([this, id, meta, cb = std::move(cb)](int error) mutable {
        if (error) {
            cb(error);
            return;
        }

        _set_state_exchange(id, meta, std::move(cb));
    });
}

void Session::_set_state_exchange(
    const RawstdUUID& id, const RawstorObjectMeta& meta,
    std::function<void(int)>&& cb
) {
    auto request = std::make_shared<RawstorOSTFrameMeta>((RawstorOSTFrameMeta){
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_SET_STATE,
                .cid = _cid_counter++,
            },
        .body = {
            .obj_id = {},
            .size = meta.size,
            .epoch = meta.epoch,
            .sync_id = meta.sync_id,
            .sync_id_history = {},
            .state = meta.state,
            .member_kind = meta.member_kind,
            .width = meta.width,
            .reserved = 0,
            .volume_id = {},
            .logical_index = meta.logical_index,
            .chunk_size = meta.chunk_size,
            .snap_version = meta.snap_version,
        },
    });
    memcpy(request->body.obj_id, id.bytes, sizeof(request->body.obj_id));
    memcpy(
        request->body.sync_id_history, meta.sync_id_history,
        sizeof(request->body.sync_id_history)
    );
    memcpy(
        request->body.volume_id, meta.volume_id, sizeof(request->body.volume_id)
    );

    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "%s\n", "set_state cmd");

    auto cb_sp = std::make_shared<std::function<void(int)>>(std::move(cb));

    _queue.write(
        fd(), request.get(), sizeof(*request),
        [q = &_queue, fd = fd(), request, cb_sp,
         trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameMeta), error
            );

            if (!error) {
                error =
                    validate_result(fd, sizeof(RawstorOSTFrameMeta), result);
            }

            if (error) {
                (*cb_sp)(error);
                return;
            }

            auto response = std::make_shared<RawstorOSTFrameResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(*response),
                    [fd, response, cb_sp,
                     trace_event](size_t result, int error) {
                        RAWSTD_TRACE_EVENT_MESSAGE(
                            trace_event, "%zu of %zu, error = %d\n", result,
                            sizeof(RawstorOSTFrameResponse), error
                        );

                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error) {
                            error = validate_response(fd, response.get(), 0);
                        }

                        if (!error) {
                            error = validate_cmd(
                                fd, response->head.cmd, RAWSTOR_CMD_SET_STATE
                            );
                        }

                        (*cb_sp)(error);
                    }
                );
            } catch (const std::system_error& e) {
                (*cb_sp)(e.code().value());
            } catch (const std::bad_alloc& e) {
                (*cb_sp)(ENOMEM);
            }
        }
    );
}

void Session::list(
    std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
) {
    /*
     * Only the plain pre-open exchange is implemented: the scan always
     * runs on a fresh control connection (Connection::list), never on an
     * object-bound session.
     */
    if (_context != nullptr) {
        cb({}, ENOTSUP);
        return;
    }

    _ensure_handshake([this, cb = std::move(cb)](int error) mutable {
        if (error) {
            cb({}, error);
            return;
        }

        _list_exchange(std::move(cb));
    });
}

void Session::_list_exchange(
    std::function<void(std::vector<RawstorObjectListEntry>&&, int)>&& cb
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "%s\n", "list_chunks cmd");

    auto request =
        std::make_shared<RawstorOSTFrameBasic>((RawstorOSTFrameBasic){
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_LIST_CHUNKS,
                    .cid = _cid_counter++,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = 0,
            },
        });

    auto cb_sp = std::make_shared<
        std::function<void(std::vector<RawstorObjectListEntry>&&, int)>>(
        std::move(cb)
    );

    _queue.write(
        fd(), request.get(), sizeof(*request),
        [q = &_queue, fd = fd(), request, cb_sp,
         trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameBasic), error
            );

            if (!error) {
                error =
                    validate_result(fd, sizeof(RawstorOSTFrameBasic), result);
            }

            if (error) {
                (*cb_sp)({}, error);
                return;
            }

            /*
             * The payload length is variable: the head is read first, the
             * record array only on success. Error responses carry no
             * payload.
             */
            auto response = std::make_shared<RawstorOSTFrameResponse>();

            try {
                q->read(
                    fd, response.get(), sizeof(*response),
                    [q, fd, response, cb_sp,
                     trace_event](size_t result, int error) {
                        RAWSTD_TRACE_EVENT_MESSAGE(
                            trace_event, "%zu of %zu, error = %d\n", result,
                            sizeof(RawstorOSTFrameResponse), error
                        );

                        if (!error) {
                            error = validate_result(
                                fd, sizeof(RawstorOSTFrameResponse), result
                            );
                        }

                        if (!error) {
                            error = validate_response(
                                fd, response.get(), response->body.len
                            );
                        }

                        if (!error) {
                            error = validate_cmd(
                                fd, response->head.cmd, RAWSTOR_CMD_LIST_CHUNKS
                            );
                        }

                        constexpr size_t record_size =
                            sizeof(RawstorOSTFrameMetaBody);
                        uint32_t len = response->body.len;

                        /* Same payload bound as the data commands. */
                        if (!error &&
                            (len % record_size != 0 || len > (1u << 26) ||
                             static_cast<uint32_t>(response->body.res) !=
                                 len / record_size)) {
                            rawstd_error(
                                "fd %d: Malformed list payload length: %u\n",
                                fd, len
                            );
                            error = EPROTO;
                        }

                        if (error) {
                            (*cb_sp)({}, error);
                            return;
                        }

                        if (len == 0) {
                            (*cb_sp)({}, 0);
                            return;
                        }

                        auto records =
                            std::make_shared<std::vector<RawstorOSTFrameMetaBody>>(
                                len / record_size
                            );

                        try {
                            q->read(
                                fd, records->data(), len,
                                [fd, response, records, len, cb_sp,
                                 trace_event](size_t result, int error) {
                                    RAWSTD_TRACE_EVENT_MESSAGE(
                                        trace_event, "%zu of %u, error = %d\n",
                                        result, len, error
                                    );

                                    if (!error) {
                                        error =
                                            validate_result(fd, len, result);
                                    }

                                    if (!error) {
                                        error = validate_hash(
                                            fd, hash(records->data(), len),
                                            response->body.hash
                                        );
                                    }

                                    if (error) {
                                        (*cb_sp)({}, error);
                                        return;
                                    }

                                    std::vector<RawstorObjectListEntry> entries;
                                    entries.reserve(records->size());
                                    for (const RawstorOSTFrameMetaBody& body :
                                         *records) {
                                        RawstorObjectListEntry entry{};
                                        memcpy(
                                            entry.obj_id, body.obj_id,
                                            sizeof(entry.obj_id)
                                        );
                                        entry.meta.size = body.size;
                                        entry.meta.epoch = body.epoch;
                                        entry.meta.sync_id = body.sync_id;
                                        memcpy(
                                            entry.meta.sync_id_history,
                                            body.sync_id_history,
                                            sizeof(entry.meta.sync_id_history)
                                        );
                                        entry.meta.state = body.state;
                                        entry.meta.member_kind =
                                            body.member_kind;
                                        entry.meta.width = body.width;
                                        memcpy(
                                            entry.meta.volume_id,
                                            body.volume_id,
                                            sizeof(entry.meta.volume_id)
                                        );
                                        entry.meta.logical_index =
                                            body.logical_index;
                                        entry.meta.chunk_size = body.chunk_size;
                                        entry.meta.snap_version =
                                            body.snap_version;
                                        entries.push_back(entry);
                                    }

                                    (*cb_sp)(std::move(entries), 0);
                                }
                            );
                        } catch (const std::system_error& e) {
                            (*cb_sp)({}, e.code().value());
                        } catch (const std::bad_alloc& e) {
                            (*cb_sp)({}, ENOMEM);
                        }
                    }
                );
            } catch (const std::system_error& e) {
                (*cb_sp)({}, e.code().value());
            } catch (const std::bad_alloc& e) {
                (*cb_sp)({}, ENOMEM);
            }
        }
    );
}

void Session::set_object(Object* object, std::function<void(int)>&& cb) {
    _set_object_exchange(&object->id(), [this, cb = std::move(cb)](int error) {
        if (error) {
            cb(error);
            return;
        }

        try {
            _context = std::make_shared<Context>(_queue, fd());
            _context->setup_recv();
        } catch (const std::system_error& e) {
            cb(e.code().value());
            return;
        } catch (const std::bad_alloc& e) {
            cb(ENOMEM);
            return;
        }

        cb(0);
    });
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpRead> op = std::make_shared<SessionOpRead>(
        _context, _cid_counter++, buf, size, offset, trace_event, std::move(cb)
    );
    _context->register_op(op);

    _queue.write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );
}

void Session::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpReadV> op = std::make_shared<SessionOpReadV>(
        _context, _cid_counter++, iov, niov, size, offset, trace_event,
        std::move(cb)
    );
    _context->register_op(op);

    _queue.write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );
}

void Session::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpWrite> op = std::make_shared<SessionOpWrite>(
        _context, _cid_counter++, buf, size, offset, trace_event, std::move(cb)
    );
    _context->register_op(op);

    _queue.writev(
        fd(), op->request_iov(), op->request_niov(),
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );
}

void Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpWriteV> op = std::make_shared<SessionOpWriteV>(
        _context, _cid_counter++, iov, niov, size, offset, trace_event,
        std::move(cb)
    );
    _context->register_op(op);

    _queue.writev(
        fd(), op->request_iov(), op->request_niov(),
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );
}

void Session::flush(std::function<void(size_t, int)>&& cb) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "fd = %d, flush\n", fd());

    std::shared_ptr<SessionOpFlush> op = std::make_shared<SessionOpFlush>(
        _context, _cid_counter++, trace_event, std::move(cb)
    );
    _context->register_op(op);

    _queue.write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );
}

} // namespace ost
} // namespace rawstor
