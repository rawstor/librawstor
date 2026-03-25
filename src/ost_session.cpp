#include "ost_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "ost_protocol.h"
#include "rawstor_internals.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.hpp>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

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

namespace {

class SessionOp;

int validate_result(int fd, size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstor_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EAGAIN;
}

int validate_response(
    int fd, const RawstorOSTFrameResponse* response
) noexcept {
    assert(response != nullptr);

    if (response->magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "fd %d: Unexpected magic number: %x != %x\n", fd, response->magic,
            RAWSTOR_MAGIC
        );
        return EPROTO;
    }

    if (response->res < 0) {
        rawstor_error(
            "fd %d: Server error: %s\n", fd, strerror(-response->res)
        );
        return EPROTO;
    }

    return 0;
}

int validate_cmd(
    int fd, enum RawstorOSTCommandType cmd, enum RawstorOSTCommandType expected
) noexcept {
    if (cmd == expected) {
        return 0;
    }

    rawstor_error("fd %d: Unexpected command: %d\n", fd, cmd);
    return EPROTO;
}

int validate_hash(int fd, uint64_t hash, uint64_t expected) noexcept {
    if (hash == expected) {
        return 0;
    }

    rawstor_error(
        "fd %d: Hash mismatch: %llx != %llx\n", fd, (unsigned long long)hash,
        (unsigned long long)expected
    );
    return EPROTO;
}

} // namespace

namespace rawstor {
namespace ost {

class Context final : public std::enable_shared_from_this<Context> {
private:
    rawstor::io::Queue& _queue;
    int _fd;
    std::unordered_map<uint16_t, std::shared_ptr<SessionOp>> _ops;
    RawstorIOEvent* _read_event;

    void _teardown_recv() noexcept;
    void _fail_in_flight(int error, bool* next_head, size_t* next_size);

    SessionOp& _find_op(uint16_t cid) {
        auto it = _ops.find(cid);
        if (it == _ops.end()) {
            rawstor_error("Unexpected cid: %u\n", cid);
            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        return *it->second.get();
    }

public:
    Context(rawstor::io::Queue& queue, int fd) :
        _queue(queue),
        _fd(fd),
        _read_event(nullptr) {}
    ~Context() { _teardown_recv(); }

    void setup_recv();

    int fd() const noexcept { return _fd; }

    void register_op(const std::shared_ptr<SessionOp>& op);

    void unregister_op(uint16_t cid) { _ops.erase(cid); }
};

} // namespace ost
} // namespace rawstor

namespace {

uint64_t hash(const void* buf, size_t size) {
    return rawstor_hash_scalar(buf, size);
}

uint64_t hash(const iovec* iov, unsigned int niov) {
    uint64_t ret;
    int res = rawstor_hash_vector(iov, niov, &ret);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}

class SessionOp {
private:
    uint16_t _cid;
    bool _in_flight;

protected:
    rawstor::TraceEvent _trace_event;
    std::shared_ptr<rawstor::ost::Context> _context;
    RawstorOSTFrameResponse _response;

    std::function<void(size_t, int)> _cb;

    inline void _dispatch(size_t result, int error) {
        _in_flight = false;
        RAWSTOR_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight end");

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
        const rawstor::TraceEvent& trace_event,
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
        RAWSTOR_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight begin");

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
        const rawstor::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _buf(buf),
        _size(size),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_READ,
            .cid = cid,
            .offset = (uint64_t)offset,
            .len = (uint32_t)_size,
            .hash = 0,
            .sync = 0,
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTOR_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(_context->fd(), response);
        }

        if (!error) {
            error =
                validate_cmd(_context->fd(), response->cmd, RAWSTOR_CMD_READ);
        }

        if (!error) {
            _hash = response->hash;
            *next_head = false;
            *next_size = _size;
        } else {
            _dispatch(0, error);
            *next_head = true;
            *next_size = 0;
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTOR_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (!error) {
            error = validate_hash(_context->fd(), hash(iov, niov), _hash);
        }

        if (result) {
            rawstor_iovec_to_buf(iov, niov, 0, _buf, result);
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
        const rawstor::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _iov(iov),
        _niov(niov),
        _size(size),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_READ,
            .cid = cid,
            .offset = (uint64_t)offset,
            .len = (uint32_t)_size,
            .hash = 0,
            .sync = 0,
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTOR_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(_context->fd(), response);
        }

        if (!error) {
            error =
                validate_cmd(_context->fd(), response->cmd, RAWSTOR_CMD_READ);
        }

        if (!error) {
            _hash = response->hash;
            *next_head = false;
            *next_size = _size;
        } else {
            _dispatch(0, error);
            *next_head = true;
            *next_size = 0;
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTOR_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (!error) {
            error = validate_hash(_context->fd(), hash(iov, niov), _hash);
        }

        if (result) {
            rawstor_iovec_to_iovec(iov, niov, 0, _iov, _niov);
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
        const rawstor::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = cid,
            .offset = (uint64_t)offset,
            .len = (uint32_t)size,
            .hash = hash(buf, size),
            .sync = 0,
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
        return sizeof(_request) + _request.len;
    }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTOR_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(_context->fd(), response);
        }

        if (!error) {
            error =
                validate_cmd(_context->fd(), response->cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(response != nullptr ? response->res : 0, error);

        if (!error) {
            *next_head = true;
            *next_size = sizeof(RawstorOSTFrameResponse);
        } else {
            *next_head = true;
            *next_size = 0;
        }
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
        const rawstor::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = cid,
            .offset = (uint64_t)offset,
            .len = (uint32_t)size,
            .hash = hash(iov, niov),
            .sync = 0,
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
        return sizeof(_request) + _request.len;
    }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTOR_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(_context->fd(), response);
        }

        if (!error) {
            error =
                validate_cmd(_context->fd(), response->cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(response != nullptr ? response->res : 0, error);

        if (!error) {
            *next_head = true;
            *next_size = sizeof(RawstorOSTFrameResponse);
        } else {
            *next_head = true;
            *next_size = 0;
        }
    }
};

} // namespace

namespace rawstor {
namespace ost {

void Context::_teardown_recv() noexcept {
    if (_read_event != nullptr) {
        try {
            _queue.cancel(_read_event);
        } catch (const std::exception& e) {
            rawstor_warning("Failed to cancel event: %s\n", e.what());
        }
        _read_event = nullptr;
    }
}

void Context::_fail_in_flight(int error, bool* next_head, size_t* next_size) {
    std::vector<std::shared_ptr<SessionOp>> in_flight_ops;
    in_flight_ops.reserve(_ops.size());
    for (const auto& i : _ops) {
        if (i.second->in_flight()) {
            in_flight_ops.push_back(i.second);
        }
    }
    for (auto i : in_flight_ops) {
        i->response_head_cb(nullptr, error, next_head, next_size);
    }
    *next_head = true;
    *next_size = 0;
}

void Context::setup_recv() {
    assert(_read_event == nullptr);

    TraceEvent trace_event = RAWSTOR_TRACE_EVENT('m', "%s\n", "multishot recv");
    _read_event = _queue.recv_multishot(
        _fd, 1u << 17, 64 * 4, sizeof(RawstorOSTFrameResponse), 0,
        [context = shared_from_this(), fd = _fd, cid = 0, is_head = true,
         size = sizeof(RawstorOSTFrameResponse), trace_event](
            const iovec* iov, unsigned int niov, size_t result, int error
        ) mutable -> size_t {
            if (error == ECANCELED) {
                return 0;
            }

            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result, size, error
            );

            if (!error) {
                error = validate_result(fd, size, result);
            }

            if (!error) {
                try {
                    if (is_head) {
                        RawstorOSTFrameResponse response;
                        rawstor_iovec_to_buf(
                            iov, niov, 0, &response, sizeof(response)
                        );
                        cid = response.cid;
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
                } catch (const std::exception& e) {
                    rawstor_error("%s\n", e.what());
                    error = EPROTO;
                }
            }

            if (error) {
                context->_fail_in_flight(error, &is_head, &size);
                context->_teardown_recv();
            }

            return size;
        }
    );
}

void Context::register_op(const std::shared_ptr<SessionOp>& op) {
    _ops[op->cid()] = op;
}

Session::Session(
    rawstor::io::Queue& queue, const URI& uri, unsigned int depth
) :
    rawstor::Session(queue, uri, depth),
    _cid_counter(0) {
    int fd = _connect();
    set_fd(fd);
}

int Session::_connect() {
    if (!uri().path().str().empty() && uri().path().str() != "/") {
        rawstor_error("Empty path expected: %s\n", uri().str().c_str());
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    int res;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO();
    }

    try {
        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            res = rawstor_socket_set_snd_timeout(fd, so_sndtimeo);
            if (res < 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            res = rawstor_socket_set_rcv_timeout(fd, so_rcvtimeo);
            if (res < 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
        if (tcp_user_timeo != 0) {
            res = rawstor_socket_set_user_timeout(fd, tcp_user_timeo);
            if (res < 0) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        sockaddr_in servaddr = {};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(uri().port());

        res = inet_pton(AF_INET, uri().hostname().c_str(), &servaddr.sin_addr);
        if (res == 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        rawstor_info("fd %d: Connecting to %s...\n", fd, uri().str().c_str());
        if (connect(fd, (sockaddr*)&servaddr, sizeof(servaddr)) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
        rawstor_info("fd %d: Connected\n", fd);

        rawstor::io::Queue::setup_fd(fd);
    } catch (...) {
        ::close(fd);
        rawstor_info("fd %d: Closed\n", fd);
        throw;
    }

    return fd;
}

void Session::_set_object(RawstorObject* object) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT('s', "%s\n", "set object");

    std::unique_ptr<rawstor::io::Queue> queue = rawstor::io::Queue::create(2);

    RawstorOSTFrameBasic request = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
        .obj_id = {},
        .offset = 0,
        .val = 0,
    };
    memcpy(request.obj_id, object->id().bytes, sizeof(request.obj_id));
    rawstor_info("%s: Setting object id\n", str().c_str());
    queue->write(
        fd(), &request, sizeof(request),
        [fd = fd(), trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameBasic), error
            );

            if (!error) {
                error =
                    validate_result(fd, sizeof(RawstorOSTFrameBasic), result);
            }

            if (error) {
                RAWSTOR_THROW_SYSTEM_ERROR(error);
            }
        }
    );

    bool completed = false;
    RawstorOSTFrameResponse response;
    queue->read(
        fd(), &response, sizeof(response),
        [fd = fd(), &response, &completed,
         trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(trace_event, "error = %d\n", error);

            completed = true;

            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameResponse), error
            );

            if (!error) {
                error = validate_result(
                    fd, sizeof(RawstorOSTFrameResponse), result
                );
            }

            if (!error) {
                error = validate_response(fd, &response);
            }

            if (!error) {
                error = validate_cmd(fd, response.cmd, RAWSTOR_CMD_SET_OBJECT);
            }

            if (error) {
                RAWSTOR_THROW_SYSTEM_ERROR(error);
            }

            rawstor_info("fd %d: Object id successfully set\n", fd);
        }
    );

    while (!completed) {
        queue->wait(rawstor_opts_wait_timeout());
    }
}

void Session::create(
    const RawstorUUID&, const RawstorObjectSpec&, std::function<void(int)>&& cb
) {
    /**
     * TODO: Implement me.
     */
    cb(0);
}

void Session::remove(const RawstorUUID&, std::function<void(int)>&&) {
    throw std::runtime_error("Session::remove() not implemented");
}

void Session::spec(
    const RawstorUUID&, std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    rawstor_info("%s: Reading object specification...\n", str().c_str());

    /**
     * TODO: Implement me.
     */
    RawstorObjectSpec ret = {
        .size = 1 << 30,
    };

    rawstor_info(
        "%s: Object specification successfully received (emulated)\n",
        str().c_str()
    );

    cb(ret, 0);
}

void Session::set_object(RawstorObject* object) {
    _set_object(object);
    _context = std::make_shared<Context>(_queue, fd());
    _context->setup_recv();
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpRead> op = std::make_shared<SessionOpRead>(
        _context, _cid_counter++, buf, size, offset, trace_event, std::move(cb)
    );
    _context->register_op(op);

    _queue.write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
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
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
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
            RAWSTOR_TRACE_EVENT_MESSAGE(
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
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpWrite> op = std::make_shared<SessionOpWrite>(
        _context, _cid_counter++, buf, size, offset, trace_event, std::move(cb)
    );
    _context->register_op(op);

    _queue.writev(
        fd(), op->request_iov(), op->request_niov(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
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
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
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
            RAWSTOR_TRACE_EVENT_MESSAGE(
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
