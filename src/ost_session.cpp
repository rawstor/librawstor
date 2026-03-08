#include "ost_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "ost_protocol.h"
#include "rawstor_internals.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
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

int validate_result(int fd, size_t size, size_t result) {
    if (result == size) {
        return 0;
    }

    rawstor_error(
        "fd %d: Unexpected event size: %zu != %zu\n", fd, result, size
    );

    return EAGAIN;
}

int validate_response(
    rawstor::ost::Session& s, const RawstorOSTFrameResponse* response
) {
    assert(response != nullptr);

    if (response->magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "%s: Unexpected magic number: %x != %x\n", s.str().c_str(),
            response->magic, RAWSTOR_MAGIC
        );
        return EPROTO;
    }

    if (response->res < 0) {
        rawstor_error(
            "%s: Server error: %s\n", s.str().c_str(), strerror(-response->res)
        );
        return EPROTO;
    }

    return 0;
}

int validate_cmd(
    rawstor::ost::Session& s, enum RawstorOSTCommandType cmd,
    enum RawstorOSTCommandType expected
) {
    if (cmd == expected) {
        return 0;
    }

    rawstor_error("%s: Unexpected command: %d\n", s.str().c_str(), cmd);
    return EPROTO;
}

int validate_hash(rawstor::ost::Session& s, uint64_t hash, uint64_t expected) {
    if (hash == expected) {
        return 0;
    }

    rawstor_error(
        "%s: Hash mismatch: %llx != %llx\n", s.str().c_str(),
        (unsigned long long)hash, (unsigned long long)expected
    );
    return EPROTO;
}

} // namespace

namespace rawstor {
namespace ost {

class Context final {
private:
    rawstor::ost::Session* _s;
    std::unordered_map<uint16_t, std::shared_ptr<SessionOp>> _ops;
    unsigned int _reads;
    RawstorOSTFrameResponse _response;

public:
    Context(rawstor::ost::Session& s) : _s(&s), _reads(0) {}

    void detach() noexcept { _s = nullptr; }

    inline rawstor::ost::Session& session() {
        if (_s == nullptr) {
            throw std::runtime_error("Context detached");
        }
        return *_s;
    }

    inline bool has_ops() const noexcept { return !_ops.empty(); }

    inline bool has_reads() const noexcept { return _reads > 0; }

    inline void add_read() noexcept { ++_reads; }

    inline void sub_read() noexcept { --_reads; }

    void register_op(const std::shared_ptr<SessionOp>& op);

    void unregister_op(uint16_t cid) { _ops.erase(cid); }

    inline RawstorOSTFrameResponse* response() noexcept { return &_response; }

    SessionOp& find_op() {
        auto it = _ops.find(_response.cid);
        if (it == _ops.end()) {
            rawstor_error("Unexpected cid: %u\n", _response.cid);
            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        return *it->second.get();
    }

    void fail_in_flight(int error);
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
    rawstor::TraceEvent _trace_event;

protected:
    std::shared_ptr<rawstor::ost::Context> _context;

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

    virtual void response_head_cb(RawstorOSTFrameResponse*, int error) = 0;
};

class SessionOpSetObjectId final : public SessionOp {
private:
    RawstorOSTFrameBasic _request;

public:
    SessionOpSetObjectId(
        const std::shared_ptr<rawstor::ost::Context>& context, uint16_t cid,
        const RawstorUUID& id, const rawstor::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(context, cid, trace_event, std::move(cb)),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .obj_id = {},
            .offset = 0,
            .val = 0,
        }) {
        memcpy(_request.obj_id, id.bytes, sizeof(_request.obj_id));
        rawstor::ost::Session& s = _context->session();
        rawstor_info("%s: Setting object id\n", s.str().c_str());
    }

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void
    response_head_cb(RawstorOSTFrameResponse* response, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, response);
        }

        if (!error) {
            error = validate_cmd(s, response->cmd, RAWSTOR_CMD_SET_OBJECT);
        }

        if (!error) {
            rawstor_info("%s: Object id successfully set\n", s.str().c_str());
        }

        _dispatch(0, error);
    }
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

    void
    response_head_cb(RawstorOSTFrameResponse* response, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, response);
        }

        if (!error) {
            error = validate_cmd(s, response->cmd, RAWSTOR_CMD_READ);
        }

        if (!error) {
            _hash = response->hash;
            s.read_response_body(*rawstor::io_queue, _buf, _size);
        } else {
            _dispatch(0, error);
        }
    }

    void response_body_cb(size_t result, int error) {
        if (!error) {
            rawstor::ost::Session& s = _context->session();
            error = validate_hash(s, hash(_buf, _size), _hash);
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

    void
    response_head_cb(RawstorOSTFrameResponse* response, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, response);
        }

        if (!error) {
            error = validate_cmd(s, response->cmd, RAWSTOR_CMD_READ);
        }

        if (!error) {
            _hash = response->hash;
            s.read_response_body(*rawstor::io_queue, _iov, _niov, _size);
        } else {
            _dispatch(0, error);
        }
    }

    void response_body_cb(size_t result, int error) {
        if (!error) {
            rawstor::ost::Session& s = _context->session();
            error = validate_hash(s, hash(_iov, _niov), _hash);
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

    void
    response_head_cb(RawstorOSTFrameResponse* response, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, response);
        }

        if (!error) {
            error = validate_cmd(s, response->cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(response != nullptr ? response->res : 0, error);
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

    void
    response_head_cb(RawstorOSTFrameResponse* response, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, response);
        }

        if (!error) {
            error = validate_cmd(s, response->cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(response != nullptr ? response->res : 0, error);
    }
};

} // namespace

namespace rawstor {
namespace ost {

void Context::register_op(const std::shared_ptr<SessionOp>& op) {
    _ops[op->cid()] = op;
}

void Context::fail_in_flight(int error) {
    std::vector<std::shared_ptr<SessionOp>> in_flight_ops;
    in_flight_ops.reserve(_ops.size());
    for (const auto& i : _ops) {
        if (i.second->in_flight()) {
            in_flight_ops.push_back(i.second);
        }
    }
    for (auto i : in_flight_ops) {
        i->response_head_cb(nullptr, error);
    }
}

Session::Session(const URI& uri, unsigned int depth) :
    rawstor::Session(uri, depth),
    _cid_counter(0),
    _context(std::make_shared<Context>(*this)) {
    int fd = _connect();
    set_fd(fd);
}

Session::~Session() {
    _context->detach();
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

void Session::read_response_head(rawstor::io::Queue& queue) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('s', "%s\n", "read response head");
    _context->add_read();
    queue.read(
        fd(), _context->response(), sizeof(*_context->response()),
        [context = _context, trace_event](size_t result, int error) mutable {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(*_context->response()), error
            );

            context->sub_read();
            if (!error) {
                error = validate_result(
                    context->session().fd(), sizeof(*context->response()),
                    result
                );
            }

            if (error) {
                context->fail_in_flight(error);
            } else {
                try {
                    SessionOp& op = context->find_op();
                    op.response_head_cb(context->response(), 0);
                } catch (const std::system_error& e) {
                    context->fail_in_flight(e.code().value());
                }
            }
            if (context->has_ops() && !context->has_reads()) {
                context->session().read_response_head(*rawstor::io_queue);
            }
        }
    );
}

void Session::read_response_body(
    rawstor::io::Queue& queue, void* buf, size_t size
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('s', "%s\n", "read response body scalar");
    _context->add_read();
    queue.read(
        fd(), buf, size,
        [context = _context, size, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result, size, error
            );

            context->sub_read();
            SessionOp& op = context->find_op();

            if (!error) {
                error = validate_result(context->session().fd(), size, result);
            }

            static_cast<SessionOpRead&>(op).response_body_cb(result, error);

            if (context->has_ops() && !context->has_reads()) {
                context->session().read_response_head(*rawstor::io_queue);
            }
        }
    );
}

void Session::read_response_body(
    rawstor::io::Queue& queue, iovec* iov, unsigned int niov, size_t size
) {
    TraceEvent trace_event =
        RAWSTOR_TRACE_EVENT('s', "%s\n", "read response body vector");
    _context->add_read();
    queue.readv(
        fd(), iov, niov,
        [context = _context, size, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result, size, error
            );

            context->sub_read();
            SessionOp& op = context->find_op();

            if (!error) {
                error = validate_result(context->session().fd(), size, result);
            }

            static_cast<SessionOpReadV&>(op).response_body_cb(result, error);

            if (context->has_ops() && !context->has_reads()) {
                context->session().read_response_head(*rawstor::io_queue);
            }
        }
    );
}

void Session::create(
    rawstor::io::Queue&, const RawstorUUID&, const RawstorObjectSpec&,
    std::function<void(int)>&& cb
) {
    /**
     * TODO: Implement me.
     */
    cb(0);
}

void Session::remove(
    rawstor::io::Queue&, const RawstorUUID&, std::function<void(int)>&&
) {
    throw std::runtime_error("Session::remove() not implemented");
}

void Session::spec(
    rawstor::io::Queue&, const RawstorUUID&,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
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

void Session::set_object(
    rawstor::io::Queue& queue, RawstorObject* object,
    std::function<void(int)>&& cb
) {
    TraceEvent trace_event = RAWSTOR_TRACE_EVENT('s', "%s\n", "set object");

    assert(_cid_counter == 0); // OST returns always 0.

    std::shared_ptr<SessionOpSetObjectId> op =
        std::make_shared<SessionOpSetObjectId>(
            _context, _cid_counter++, object->id(), trace_event,
            [cb](size_t, int error) { cb(error); }
        );
    _context->register_op(op);

    queue.write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().session().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );

    if (!_context->has_reads()) {
        read_response_head(queue);
    }

    _o = object;
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

    io_queue->write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().session().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
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

    io_queue->write(
        fd(), op->request_data(), op->request_size(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().session().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
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

    io_queue->writev(
        fd(), op->request_iov(), op->request_niov(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().session().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
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

    io_queue->writev(
        fd(), op->request_iov(), op->request_niov(),
        [op, trace_event](size_t result, int error) {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(
                    op->context().session().fd(), op->request_size(), result
                );
            }

            op->request_cb(error);
        }
    );

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}

} // namespace ost
} // namespace rawstor
