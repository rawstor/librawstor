#include "ost_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "ost_protocol.h"
#include "rawstor_internals.hpp"
#include "task.hpp"

#include <rawstorio/queue.hpp>
#include <rawstorio/task.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

#include <arpa/inet.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <system_error>
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

#define t_trace(t, result, error)                                              \
    rawstor_debug(                                                             \
        "%s(): %zu of %zu, error = %d\n", __FUNCTION__, (result), (t).size(),  \
        error                                                                  \
    )

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

public:
    Context(rawstor::ost::Session& s) : _s(&s) {}

    void detach() noexcept { _s = nullptr; }

    inline rawstor::ost::Session& session() {
        if (_s == nullptr) {
            throw std::runtime_error("Context detached");
        }
        return *_s;
    }

    inline bool has_ops() const noexcept { return !_ops.empty(); }

    void register_op(const std::shared_ptr<SessionOp>& op);

    void unregister_op(uint16_t cid) { _ops.erase(cid); }

    SessionOp& find_op(uint16_t cid) {
        auto it = _ops.find(cid);
        if (it == _ops.end()) {
            rawstor_error("Unexpected cid: %u\n", cid);
            RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
        }

        return *it->second.get();
    }

    void fail_in_flight(int error);
};

} // namespace ost
} // namespace rawstor

namespace {

uint64_t hash(void* buf, size_t size) {
    return rawstor_hash_scalar(buf, size);
}

uint64_t hash(iovec* iov, unsigned int niov) {
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
    RawstorObject* _o;
    std::shared_ptr<rawstor::ost::Context> _context;

    std::unique_ptr<rawstor::Task> _t;

    inline void _dispatch(size_t result, int error) {
        _in_flight = false;
#ifdef RAWSTOR_TRACE_EVENTS
        _t->trace(__FILE__, __LINE__, __FUNCTION__, "in-flight end");
#endif

        try {
            (*_t)(_o, result, error);
        } catch (...) {
            _context->unregister_op(_cid);
            throw;
        }

        _context->unregister_op(_cid);
    }

public:
    SessionOp(
        RawstorObject* o, const std::shared_ptr<rawstor::ost::Context>& context,
        uint16_t cid, std::unique_ptr<rawstor::Task> t
    ) :
        _cid(cid),
        _in_flight(false),
        _o(o),
        _context(context),
        _t(std::move(t)) {}

    SessionOp(const SessionOp&) = delete;
    SessionOp(SessionOp&&) = delete;
    virtual ~SessionOp() = default;

    SessionOp& operator=(const SessionOp&) = delete;
    SessionOp& operator=(SessionOp&&) = delete;

    inline rawstor::ost::Context& context() noexcept { return *_context; }

    inline uint16_t cid() const noexcept { return _cid; }

    inline bool in_flight() const noexcept { return _in_flight; }

    void request_cb(int error) {
        _in_flight = true;
#ifdef RAWSTOR_TRACE_EVENTS
        _t->trace(__FILE__, __LINE__, __FUNCTION__, "in-flight begin");
#endif

        if (error) {
            _dispatch(0, error);
        }
    }

    virtual size_t
    response_head_cb(RawstorOSTFrameResponse* head, int error) = 0;
    virtual void response_body_cb(iovec*, unsigned int, size_t, int) {}
};

class SessionOpSetObjectId final : public SessionOp {
public:
    SessionOpSetObjectId(
        RawstorObject* o, const std::shared_ptr<rawstor::ost::Context>& context,
        uint16_t cid, std::unique_ptr<rawstor::Task> t
    ) :
        SessionOp(o, context, cid, std::move(t)) {
        rawstor::ost::Session& s = _context->session();
        rawstor_info("%s: Setting object id\n", s.str().c_str());
    }

    size_t response_head_cb(RawstorOSTFrameResponse* head, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, head);
        }

        if (!error) {
            error = validate_cmd(s, head->cmd, RAWSTOR_CMD_SET_OBJECT);
        }

        if (!error) {
            rawstor_info("%s: Object id successfully set\n", s.str().c_str());
        }

        _dispatch(0, error);

        return 0;
    }
};

class SessionOpRead final : public SessionOp {
private:
    uint64_t _hash;

public:
    SessionOpRead(
        RawstorObject* o, const std::shared_ptr<rawstor::ost::Context>& context,
        uint16_t cid, std::unique_ptr<rawstor::TaskScalar> t
    ) :
        SessionOp(o, context, cid, std::move(t)),
        _hash(0) {}

    size_t size() const noexcept {
        return static_cast<rawstor::TaskScalar*>(_t.get())->size();
    }

    off_t offset() const noexcept {
        return static_cast<rawstor::TaskScalar*>(_t.get())->offset();
    }

    size_t response_head_cb(RawstorOSTFrameResponse* head, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, head);
        }

        if (!error) {
            error = validate_cmd(s, head->cmd, RAWSTOR_CMD_READ);
        }

        if (error) {
            _dispatch(0, error);
            return 0;
        }

        _hash = head->hash;

        return head->res;
    }

    void response_body_cb(
        iovec* iov, unsigned int niov, size_t, int error
    ) override {
        if (!error) {
            rawstor::ost::Session& s = _context->session();
            error = validate_hash(s, hash(iov, niov), _hash);
        }

        size_t result = 0;

        if (!error) {
            result = rawstor_iovec_to_buf(
                iov, niov, 0,
                static_cast<rawstor::TaskScalar*>(_t.get())->buf(),
                static_cast<rawstor::TaskScalar*>(_t.get())->size()
            );
        }

        _dispatch(result, error);
    }
};

class SessionOpReadV final : public SessionOp {
private:
    uint64_t _hash;

public:
    SessionOpReadV(
        RawstorObject* o, const std::shared_ptr<rawstor::ost::Context>& context,
        uint16_t cid, std::unique_ptr<rawstor::TaskVector> t
    ) :
        SessionOp(o, context, cid, std::move(t)),
        _hash(0) {}

    size_t size() const noexcept {
        return static_cast<rawstor::TaskVector*>(_t.get())->size();
    }

    off_t offset() const noexcept {
        return static_cast<rawstor::TaskVector*>(_t.get())->offset();
    }

    size_t response_head_cb(RawstorOSTFrameResponse* head, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, head);
        }

        if (!error) {
            error = validate_cmd(s, head->cmd, RAWSTOR_CMD_READ);
        }

        if (error) {
            _dispatch(0, error);
            return 0;
        }

        _hash = head->hash;

        return head->res;
    }

    void response_body_cb(
        iovec* iov, unsigned int niov, size_t, int error
    ) override {
        if (!error) {
            rawstor::ost::Session& s = _context->session();
            error = validate_hash(s, hash(iov, niov), _hash);
        }

        size_t result = 0;

        if (!error) {
            result = rawstor_iovec_to_iovec(
                iov, niov, 0,
                static_cast<rawstor::TaskVector*>(_t.get())->iov(),
                static_cast<rawstor::TaskVector*>(_t.get())->niov()
            );
        }

        _dispatch(result, error);
    }
};

class SessionOpWrite final : public SessionOp {
public:
    SessionOpWrite(
        RawstorObject* o, const std::shared_ptr<rawstor::ost::Context>& context,
        uint16_t cid, std::unique_ptr<rawstor::TaskScalar> t
    ) :
        SessionOp(o, context, cid, std::move(t)) {}

    void* buf() noexcept {
        return static_cast<rawstor::TaskScalar*>(_t.get())->buf();
    }

    size_t size() const noexcept {
        return static_cast<rawstor::TaskScalar*>(_t.get())->size();
    }

    off_t offset() const noexcept {
        return static_cast<rawstor::TaskScalar*>(_t.get())->offset();
    }

    size_t response_head_cb(RawstorOSTFrameResponse* head, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, head);
        }

        if (!error) {
            error = validate_cmd(s, head->cmd, RAWSTOR_CMD_WRITE);
        }

        if (error) {
            _dispatch(0, error);
            return 0;
        }

        _dispatch(head->res, error);

        return 0;
    }
};

class SessionOpWriteV final : public SessionOp {
public:
    SessionOpWriteV(
        RawstorObject* o, const std::shared_ptr<rawstor::ost::Context>& context,
        uint16_t cid, std::unique_ptr<rawstor::TaskVector> t
    ) :
        SessionOp(o, context, cid, std::move(t)) {}

    iovec* iov() noexcept {
        return static_cast<rawstor::TaskVector*>(_t.get())->iov();
    }

    unsigned int niov() noexcept {
        return static_cast<rawstor::TaskVector*>(_t.get())->niov();
    }

    size_t size() const noexcept {
        return static_cast<rawstor::TaskVector*>(_t.get())->size();
    }

    off_t offset() const noexcept {
        return static_cast<rawstor::TaskVector*>(_t.get())->offset();
    }

    size_t response_head_cb(RawstorOSTFrameResponse* head, int error) override {
        rawstor::ost::Session& s = _context->session();

        if (!error) {
            error = validate_response(s, head);
        }

        if (!error) {
            error = validate_cmd(s, head->cmd, RAWSTOR_CMD_WRITE);
        }

        if (error) {
            _dispatch(0, error);
            return 0;
        }

        _dispatch(head->res, error);

        return 0;
    }
};

class RequestScalar : public rawstor::io::TaskScalar {
protected:
    std::shared_ptr<SessionOp> _op;

public:
    explicit RequestScalar(const std::shared_ptr<SessionOp>& op) : _op(op) {}

    void operator()(size_t result, int error) override {
        t_trace(*this, result, error);

        if (!error) {
            error =
                validate_result(_op->context().session().fd(), size(), result);
        }

        _op->request_cb(error);
    }
};

class RequestVector : public rawstor::io::TaskVector {
protected:
    std::shared_ptr<SessionOp> _op;

public:
    explicit RequestVector(const std::shared_ptr<SessionOp>& op) : _op(op) {}

    void operator()(size_t result, int error) override {
        t_trace(*this, result, error);

        if (!error) {
            error =
                validate_result(_op->context().session().fd(), size(), result);
        }

        _op->request_cb(error);
    }
};

class RequestBasic : public RequestScalar {
protected:
    RawstorOSTFrameBasic _request;

public:
    RequestBasic(
        const std::shared_ptr<SessionOp>& op, const RawstorUUID& id,
        const RawstorOSTCommandType& cmd
    ) :
        RequestScalar(op),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = cmd,
            .obj_id = {},
            .offset = 0,
            .val = 0,
        }) {
        memcpy(_request.obj_id, id.bytes, sizeof(_request.obj_id));
    }

    void* buf() noexcept override { return &_request; }

    size_t size() const noexcept override { return sizeof(_request); }
};

class RequestSetObjectId final : public RequestBasic {
public:
    RequestSetObjectId(
        const std::shared_ptr<SessionOp>& op, const RawstorUUID& id
    ) :
        RequestBasic(op, id, RAWSTOR_CMD_SET_OBJECT) {}
};

class RequestIOScalar : public RequestScalar {
protected:
    RawstorOSTFrameIO _request;

public:
    RequestIOScalar(
        const std::shared_ptr<SessionOpRead>& op,
        const RawstorOSTCommandType& cmd, uint64_t hash
    ) :
        RequestScalar(op),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = cmd,
            .cid = op->cid(),
            .offset = (uint64_t)op->offset(),
            .len = (uint32_t)op->size(),
            .hash = hash,
            .sync = 0,
        }) {}

    RequestIOScalar(
        const std::shared_ptr<SessionOpReadV>& op,
        const RawstorOSTCommandType& cmd, uint64_t hash
    ) :
        RequestScalar(op),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = cmd,
            .cid = op->cid(),
            .offset = (uint64_t)op->offset(),
            .len = (uint32_t)op->size(),
            .hash = hash,
            .sync = 0,
        }) {}
};

class RequestIOVector : public RequestVector {
protected:
    RawstorOSTFrameIO _request;

public:
    RequestIOVector(
        const std::shared_ptr<SessionOpWrite>& op,
        const RawstorOSTCommandType& cmd, uint64_t hash
    ) :
        RequestVector(op),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = cmd,
            .cid = op->cid(),
            .offset = (uint64_t)op->offset(),
            .len = (uint32_t)op->size(),
            .hash = hash,
            .sync = 0,
        }) {}

    RequestIOVector(
        const std::shared_ptr<SessionOpWriteV>& op,
        const RawstorOSTCommandType& cmd, uint64_t hash
    ) :
        RequestVector(op),
        _request({
            .magic = RAWSTOR_MAGIC,
            .cmd = cmd,
            .cid = op->cid(),
            .offset = (uint64_t)op->offset(),
            .len = (uint32_t)op->size(),
            .hash = hash,
            .sync = 0,
        }) {}
};

class RequestCmdRead final : public RequestIOScalar {
public:
    explicit RequestCmdRead(const std::shared_ptr<SessionOpRead>& op) :
        RequestIOScalar(op, RAWSTOR_CMD_READ, 0) {}

    explicit RequestCmdRead(const std::shared_ptr<SessionOpReadV>& op) :
        RequestIOScalar(op, RAWSTOR_CMD_READ, 0) {}

    void* buf() noexcept override { return &_request; }

    size_t size() const noexcept override { return sizeof(_request); }
};

class RequestCmdWrite final : public RequestIOVector {
private:
    std::vector<iovec> _iov;

public:
    explicit RequestCmdWrite(const std::shared_ptr<SessionOpWrite>& op) :
        RequestIOVector(op, RAWSTOR_CMD_WRITE, hash(op->buf(), op->size())) {
        _iov.reserve(2);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        _iov.push_back({
            .iov_base = op->buf(),
            .iov_len = op->size(),
        });
    }

    explicit RequestCmdWrite(const std::shared_ptr<SessionOpWriteV>& op) :
        RequestIOVector(op, RAWSTOR_CMD_WRITE, hash(op->iov(), op->niov())) {
        _iov.reserve(op->niov() + 1);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        for (unsigned int i = 0; i < op->niov(); ++i) {
            _iov.push_back(op->iov()[i]);
        }
    }

    iovec* iov() noexcept override { return _iov.data(); }

    unsigned int niov() const noexcept override { return _iov.size(); }

    size_t size() const noexcept override {
        return sizeof(_request) + _request.len;
    }
};

class ResponseMultishot final : public rawstor::io::TaskVectorExternal {
private:
    std::shared_ptr<rawstor::ost::Context> _context;
    RawstorOSTFrameResponse _head;
    SessionOp* _op;
    size_t _body_size;

public:
    explicit ResponseMultishot(
        const std::shared_ptr<rawstor::ost::Context>& context
    ) :
        _context(context),
        _op(nullptr),
        _body_size(0) {}

    void operator()(size_t result, int error) override {
        t_trace(*this, result, error);

        if (!error) {
            error = validate_result(_context->session().fd(), size(), result);
        }

        if (_op == nullptr && result != sizeof(_head)) {
            error = EPROTO;
        }

        if (error) [[unlikely]] {
            _context->fail_in_flight(error);
            return;
        }

        try {
            if (_op == nullptr) {
                rawstor_iovec_to_buf(iov(), niov(), 0, &_head, sizeof(_head));

                _op = &_context->find_op(_head.cid);
                _body_size = _op->response_head_cb(&_head, 0);
                if (_body_size == 0) {
                    _op = nullptr;
                }
            } else {
                _op->response_body_cb(iov(), niov(), result, error);
            }
        } catch (const std::system_error& e) {
            _context->fail_in_flight(e.code().value());
        }
    }

    inline size_t size() const noexcept override {
        return _body_size == 0 ? sizeof(_head) : _body_size;
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
    _read_event(nullptr),
    _cid_counter(0),
    _context(std::make_shared<Context>(*this)) {
    int fd = _connect();
    set_fd(fd);
    std::unique_ptr<ResponseMultishot> res =
        std::make_unique<ResponseMultishot>(_context);
    _read_event =
        io_queue->recv_multishot(fd, std::move(res), 1u << 17, 64 * 4, 0);
}

Session::~Session() {
    if (_read_event != nullptr) {
        try {
            io_queue->cancel(_read_event);
        } catch (const std::system_error&) {
        }
    }
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

void Session::create(
    rawstor::io::Queue&, const RawstorUUID&, const RawstorObjectSpec&,
    std::unique_ptr<rawstor::Task> t
) {
    /**
     * TODO: Implement me.
     */
    (*t)(nullptr, 0, 0);
}

void Session::remove(
    rawstor::io::Queue&, const RawstorUUID&, std::unique_ptr<rawstor::Task>
) {
    throw std::runtime_error("Session::remove() not implemented");
}

void Session::spec(
    rawstor::io::Queue&, const RawstorUUID&, RawstorObjectSpec* sp,
    std::unique_ptr<rawstor::Task> t
) {
    rawstor_info("%s: Reading object specification...\n", str().c_str());

    /**
     * TODO: Implement me.
     */
    *sp = {
        .size = 1 << 30,
    };

    rawstor_info(
        "%s: Object specification successfully received (emulated)\n",
        str().c_str()
    );

    (*t)(nullptr, 0, 0);
}

void Session::set_object(
    rawstor::io::Queue& queue, RawstorObject* object,
    std::unique_ptr<rawstor::Task> t
) {
    assert(_cid_counter == 0); // OST returns always 0.

    std::shared_ptr<SessionOpSetObjectId> op =
        std::make_shared<SessionOpSetObjectId>(
            object, _context, _cid_counter++, std::move(t)
        );
    _context->register_op(op);

    std::unique_ptr<RequestSetObjectId> req =
        std::make_unique<RequestSetObjectId>(op, object->id());
    queue.write(fd(), std::move(req));

    _o = object;
}

void Session::pread(std::unique_ptr<rawstor::TaskScalar> t) {
    rawstor_debug(
        "%s(): fd = %d, offset = %jd, size = %zu\n", __FUNCTION__, fd(),
        (intmax_t)t->offset(), t->size()
    );

    std::shared_ptr<SessionOpRead> op = std::make_shared<SessionOpRead>(
        _o, _context, _cid_counter++, std::move(t)
    );
    _context->register_op(op);

    std::unique_ptr<RequestCmdRead> req = std::make_unique<RequestCmdRead>(op);
    io_queue->write(fd(), std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}

void Session::preadv(std::unique_ptr<rawstor::TaskVector> t) {
    rawstor_debug(
        "%s(): fd = %d, offset = %jd, niov = %u, size = %zu\n", __FUNCTION__,
        fd(), (intmax_t)t->offset(), t->niov(), t->size()
    );

    std::shared_ptr<SessionOpReadV> op = std::make_shared<SessionOpReadV>(
        _o, _context, _cid_counter++, std::move(t)
    );
    _context->register_op(op);

    std::unique_ptr<RequestCmdRead> req = std::make_unique<RequestCmdRead>(op);
    io_queue->write(fd(), std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}

void Session::pwrite(std::unique_ptr<rawstor::TaskScalar> t) {
    rawstor_debug(
        "%s(): fd = %d, offset = %jd, size = %zu\n", __FUNCTION__, fd(),
        (intmax_t)t->offset(), t->size()
    );

    std::shared_ptr<SessionOpWrite> op = std::make_shared<SessionOpWrite>(
        _o, _context, _cid_counter++, std::move(t)
    );
    _context->register_op(op);

    std::unique_ptr<RequestCmdWrite> req =
        std::make_unique<RequestCmdWrite>(op);
    io_queue->writev(fd(), std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}

void Session::pwritev(std::unique_ptr<rawstor::TaskVector> t) {
    rawstor_debug(
        "%s(): fd = %d, offset = %jd, niov = %u, size = %zu\n", __FUNCTION__,
        fd(), (intmax_t)t->offset(), t->niov(), t->size()
    );

    std::shared_ptr<SessionOpWriteV> op = std::make_shared<SessionOpWriteV>(
        _o, _context, _cid_counter++, std::move(t)
    );
    _context->register_op(op);

    std::unique_ptr<RequestCmdWrite> req =
        std::make_unique<RequestCmdWrite>(op);
    io_queue->writev(fd(), std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}

} // namespace ost
} // namespace rawstor
