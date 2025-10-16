#include "ost_driver.hpp"

#include "object.hpp"
#include "opts.h"
#include "ost_protocol.h"
#include "rawstor_internals.hpp"

#include <rawstorio/event.hpp>
#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

#include <arpa/inet.h>

#include <algorithm>
#include <iterator>
#include <memory>
#include <sstream>
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


#define op_trace(cid, event) \
    rawstor_debug( \
        "[%u] %s(): %zu of %zu\n", \
        (cid), __FUNCTION__, \
        event->result(), \
        event->size())


namespace {


class DriverOp;


void validate_event(RawstorIOEvent *event) {
    int error = event->error();
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (event->result() != event->size()) {
        rawstor_error(
            "fd %d: Unexpected event size: %zu != %zu\n",
            event->fd(),
            event->result(),
            event->size());
        RAWSTOR_THROW_SYSTEM_ERROR(EAGAIN);
    }
}


void validate_response(rawstor::ost::Driver &s, const RawstorOSTFrameResponse &response) {
    if (response.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "%s: Unexpected magic number: %x != %x\n",
            s.str().c_str(),
            response.magic, RAWSTOR_MAGIC);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    if (response.res < 0) {
        rawstor_error(
            "%s: Server error: %s\n",
            s.str().c_str(),
            strerror(-response.res));
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }
}


void validate_cmd(
    rawstor::ost::Driver &s,
    enum RawstorOSTCommandType cmd, enum RawstorOSTCommandType expected)
{
    if (cmd != expected) {
        rawstor_error("%s: Unexpected command: %d\n", s.str().c_str(), cmd);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }
}


void validate_hash(rawstor::ost::Driver &s, uint64_t hash, uint64_t expected) {
    if (hash != expected) {
        rawstor_error(
            "%s: Hash mismatch: %llx != %llx\n",
            s.str().c_str(),
            (unsigned long long)hash,
            (unsigned long long)expected);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }
}


}


namespace rawstor {
namespace ost {


class Context final {
    private:
        rawstor::ost::Driver *_s;
        std::unordered_map<uint16_t, std::shared_ptr<DriverOp>> _ops;
        unsigned int _reads;

    public:
        Context(rawstor::ost::Driver &s):
            _s(&s),
            _reads(0)
        {}

        void detach() noexcept {
            _s = nullptr;
        }

        inline rawstor::ost::Driver& session() {
            if (_s == nullptr) {
                throw std::runtime_error("Context detached");
            }
            return *_s;
        }

        inline bool has_reads() const noexcept {
            return _reads > 0;
        }

        inline void add_read() noexcept {
            ++_reads;
        }

        inline void sub_read() noexcept {
            --_reads;
        }

        void register_op(const std::shared_ptr<DriverOp> &op);

        void unregister_op(uint16_t cid) {
            _ops.erase(cid);
        }

        DriverOp& find_op(uint16_t cid) {
            auto it = _ops.find(cid);
            if (it == _ops.end()) {
                rawstor_error("Unexpected cid: %u\n", cid);
                RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
            }

            return *it->second.get();
        }

        void fail_all(int error);
};


}} // rawstor::ost


namespace {


uint64_t hash(void *buf, size_t size) {
    return rawstor_hash_scalar(buf, size);
}


uint64_t hash(iovec *iov, unsigned int niov) {
    uint64_t ret;
    int res = rawstor_hash_vector(iov, niov, &ret);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}


class DriverOp {
    private:
        uint16_t _cid;

    protected:
        std::shared_ptr<rawstor::ost::Context> _context;
        bool _in_flight;

        size_t _size;
        RawstorCallback *_cb;
        void *_data;

    public:
        DriverOp(
            const std::shared_ptr<rawstor::ost::Context> &context, uint16_t cid,
            size_t size,
            RawstorCallback *cb, void *data):
            _cid(cid),
            _context(context),
            _in_flight(false),
            _size(size),
            _cb(cb),
            _data(data)
        {}

        DriverOp(const DriverOp &) = delete;
        DriverOp(DriverOp &&) = delete;
        virtual ~DriverOp() {}

        DriverOp& operator=(const DriverOp &) = delete;
        DriverOp& operator=(DriverOp &&) = delete;

        inline uint16_t cid() const noexcept {
            return _cid;
        }

        inline bool in_flight() const noexcept {
            return _in_flight;
        }

        inline void dispatch(size_t res, int error) {
            RawstorObject *o = _context->session().object();

            _in_flight = false;

            int ret = _cb(o, _size, res, error, _data);

            _context->unregister_op(_cid);

            if (ret) {
                RAWSTOR_THROW_SYSTEM_ERROR(-ret);
            }
        }

        void request_cb(RawstorIOEvent *event) {
            RawstorObject *o = _context->session().object();
            int error = 0;

            try {
                op_trace(_cid, event);

                validate_event(event);

                _in_flight = true;
            } catch (const std::system_error &e) {
                error = e.code().value();
            }

            int res = 0;
            if (error) {
                res = _cb(o, _size, 0, error, _data);
            }

            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }

        virtual void response_head_cb(RawstorOSTFrameResponse &) = 0;

        virtual void response_body_cb(RawstorIOEvent *) {
        }
};


class DriverOpSetObjectId final: public DriverOp {
    public:
        DriverOpSetObjectId(
            const std::shared_ptr<rawstor::ost::Context> &context,
            uint16_t cid,
            RawstorCallback *cb, void *data):
            DriverOp(context, cid, 0, cb, data)
        {}

        void response_head_cb(RawstorOSTFrameResponse &response) {
            rawstor::ost::Driver &s = _context->session();
            int error = 0;

            try {
                validate_cmd(s, response.cmd, RAWSTOR_CMD_SET_OBJECT);
                validate_response(s, response);
                rawstor_info(
                    "%s: Object id successfully set\n", s.str().c_str());
            } catch (std::system_error &e) {
                error = e.code().value();
            }

            dispatch(0, error);
        }
};


class DriverOpRead final: public DriverOp {
    private:
        void *_buf;
        uint64_t _hash;

    public:
        DriverOpRead(
            const std::shared_ptr<rawstor::ost::Context> &context,
            uint16_t cid, void *buf, size_t size,
            RawstorCallback *cb, void *data):
            DriverOp(context, cid, size, cb, data),
            _buf(buf),
            _hash(0)
        {}

        void response_head_cb(RawstorOSTFrameResponse &response) {
            rawstor::ost::Driver &s = _context->session();
            int error = 0;

            try {
                validate_cmd(s, response.cmd, RAWSTOR_CMD_READ);
                validate_response(s, response);

                _hash = response.hash;

            } catch (std::system_error &e) {
                error = e.code().value();
            }

            if (error) {
                dispatch(response.res, error);
            } else {
                s.read_response_body(
                    *rawstor::io_queue, cid(), _buf, _size);
            }
        }

        void response_body_cb(RawstorIOEvent *event) {
            rawstor::ost::Driver &s = _context->session();
            op_trace(cid(), event);

            int error = 0;

            try {
                validate_event(event);
                validate_hash(s, hash(_buf, _size), _hash);
            } catch (std::system_error &e) {
                error = e.code().value();
            }

            dispatch(_size, error);
        }
};


class DriverOpReadV final: public DriverOp {
    private:
        iovec *_iov;
        unsigned int _niov;
        uint64_t _hash;

    public:
        DriverOpReadV(
            const std::shared_ptr<rawstor::ost::Context> &context,
            uint16_t cid, iovec *iov, unsigned int niov, size_t size,
            RawstorCallback *cb, void *data):
            DriverOp(context, cid, size, cb, data),
            _iov(iov),
            _niov(niov),
            _hash(0)
        {}

        void response_head_cb(RawstorOSTFrameResponse &response) {
            rawstor::ost::Driver &s = _context->session();
            int error = 0;

            try {
                validate_cmd(s, response.cmd, RAWSTOR_CMD_READ);
                validate_response(s, response);
                _hash = response.hash;
            } catch (std::system_error &e) {
                error = e.code().value();
            }

            if (error) {
                dispatch(response.res, error);
            } else {
                s.read_response_body(
                    *rawstor::io_queue, cid(), _iov, _niov, _size);
            }
        }

        void response_body_cb(RawstorIOEvent *event) {
            rawstor::ost::Driver &s = _context->session();
            op_trace(cid(), event);

            int error = 0;

            try {
                validate_event(event);
                validate_hash(s, hash(_iov, _niov), _hash);
            } catch (std::system_error &e) {
                error = e.code().value();
            }

            dispatch(_size, error);
        }
};


class DriverOpWrite final: public DriverOp {
    public:
        DriverOpWrite(
            const std::shared_ptr<rawstor::ost::Context> &context,
            uint16_t cid, size_t size,
            RawstorCallback *cb, void *data):
            DriverOp(context, cid, size, cb, data)
        {}

        void response_head_cb(RawstorOSTFrameResponse &response) {
            rawstor::ost::Driver &s = _context->session();
            int error = 0;

            try {
                validate_cmd(s, response.cmd, RAWSTOR_CMD_WRITE);
                validate_response(s, response);
            } catch (std::system_error &e) {
                error = e.code().value();
            }

            dispatch(response.res, error);
        }
};


class RequestScalar: public rawstor::io::TaskScalar {
    protected:
        std::shared_ptr<DriverOp> _op;

    public:
        RequestScalar(int fd, const std::shared_ptr<DriverOp> &op):
            rawstor::io::TaskScalar(fd),
            _op(op)
        {}

        void operator()(RawstorIOEvent *event) {
            _op->request_cb(event);
        }
};


class RequestVector: public rawstor::io::TaskVector {
    protected:
        std::shared_ptr<DriverOp> _op;

    public:
        RequestVector(int fd, const std::shared_ptr<DriverOp> &op):
            rawstor::io::TaskVector(fd),
            _op(op)
        {}

        void operator()(RawstorIOEvent *event) {
            _op->request_cb(event);
        }
};


class RequestBasic: public RequestScalar {
    protected:
        RawstorOSTFrameBasic _request;

    public:
        RequestBasic(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            const RawstorUUID &id,
            const RawstorOSTCommandType &cmd):
            RequestScalar(fd, op),
            _request({
                .magic = RAWSTOR_MAGIC,
                .cmd = cmd,
                .obj_id = {},
                .offset = 0,
                .val = 0,
            })
        {
            memcpy(_request.obj_id, id.bytes, sizeof(_request.obj_id));
        }

        void* buf() noexcept {
            return &_request;
        }

        size_t size() const noexcept {
            return sizeof(_request);
        }
};


class RequestSetObjectId final: public RequestBasic {
    public:
        RequestSetObjectId(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            const RawstorUUID &id):
            RequestBasic(fd, op, id, RAWSTOR_CMD_SET_OBJECT)
        {}
};


class RequestIOScalar: public RequestScalar {
    protected:
        RawstorOSTFrameIO _request;

    public:
        RequestIOScalar(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            const RawstorOSTCommandType &cmd,
            size_t size, off_t offset, uint64_t hash):
            RequestScalar(fd, op),
            _request({
                .magic = RAWSTOR_MAGIC,
                .cmd = cmd,
                .cid = op->cid(),
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash,
                .sync = 0,
            })
        {}
};


class RequestIOVector: public RequestVector {
    protected:
        RawstorOSTFrameIO _request;

    public:
        RequestIOVector(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            const RawstorOSTCommandType &cmd,
            size_t size, off_t offset, uint64_t hash):
            RequestVector(fd, op),
            _request({
                .magic = RAWSTOR_MAGIC,
                .cmd = cmd,
                .cid = op->cid(),
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash,
                .sync = 0,
            })
        {}
};


class RequestCmdRead final: public RequestIOScalar {
    public:
        RequestCmdRead(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            size_t size, off_t offset):
            RequestIOScalar(
                fd, op, RAWSTOR_CMD_READ,
                size, offset, 0)
        {}

        void* buf() noexcept {
            return &_request;
        }

        size_t size() const noexcept {
            return sizeof(_request);
        }
};


class RequestCmdWrite final: public RequestIOVector {
    private:
        std::vector<iovec> _iov;

    public:
        RequestCmdWrite(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            void *buf, size_t size, off_t offset):
            RequestIOVector(
                fd, op, RAWSTOR_CMD_WRITE,
                size, offset, hash(buf, size))
        {
            _iov.reserve(2);
            _iov.push_back({
                .iov_base = &_request,
                .iov_len = sizeof(_request),
            });
            _iov.push_back({
                .iov_base = buf,
                .iov_len = size,
            });
        }

        RequestCmdWrite(
            int fd,
            const std::shared_ptr<DriverOp> &op,
            iovec *iov, unsigned int niov, size_t size, off_t offset):
            RequestIOVector(
                fd, op, RAWSTOR_CMD_WRITE,
                size, offset, hash(iov, niov))
        {
            _iov.reserve(niov + 1);
            _iov.push_back({
                .iov_base = &_request,
                .iov_len = sizeof(_request),
            });
            for (unsigned int i = 0; i < niov; ++i) {
                _iov.push_back(iov[i]);
            }
        }

        iovec* iov() noexcept {
            return _iov.data();
        }

        unsigned int niov() const noexcept {
            return _iov.size();
        }

        size_t size() const noexcept {
            return sizeof(_request) + _request.len;
        }
};


class ResponseHead final: public rawstor::io::TaskScalar {
    private:
        std::shared_ptr<rawstor::ost::Context> _context;
        RawstorOSTFrameResponse _response;

    public:
        ResponseHead(
            int fd,
            const std::shared_ptr<rawstor::ost::Context> &context):
            rawstor::io::TaskScalar(fd),
            _context(context)
        {
            _context->add_read();
        }

        void operator()(RawstorIOEvent *event) {
            _context->sub_read();

            try {
                validate_event(event);
                op_trace(_response.cid, event);

                DriverOp &op = _context->find_op(_response.cid);
                op.response_head_cb(_response);

                if (!_context->has_reads()) {
                    _context->session().read_response_head(*rawstor::io_queue);
                }
            } catch (std::system_error &e) {
                _context->fail_all(e.code().value());
            }
        }

        inline void* buf() noexcept {
            return &_response;
        }

        inline size_t size() const noexcept {
            return sizeof(_response);
        }
};


class ResponseBodyScalar final: public rawstor::io::TaskScalar {
    private:
        std::shared_ptr<rawstor::ost::Context> _context;
        uint16_t _cid;
        void *_buf;
        size_t _size;

    public:
        ResponseBodyScalar(
            int fd,
            const std::shared_ptr<rawstor::ost::Context> &context,
            uint16_t cid,
            void *buf, size_t size):
            rawstor::io::TaskScalar(fd),
            _context(context),
            _cid(cid),
            _buf(buf),
            _size(size)
        {
            _context->add_read();
        }

        void operator()(RawstorIOEvent *event) {
            _context->sub_read();

            DriverOp &op = _context->find_op(_cid);
            op.response_body_cb(event);

            if (!_context->has_reads()) {
                _context->session().read_response_head(*rawstor::io_queue);
            }
        }

        void* buf() noexcept {
            return _buf;
        }
        size_t size() const noexcept {
            return _size;
        }
};


class ResponseBodyVector final: public rawstor::io::TaskVector {
    private:
        std::shared_ptr<rawstor::ost::Context> _context;
        uint16_t _cid;
        iovec *_iov;
        unsigned int _niov;
        size_t _size;

    public:
        ResponseBodyVector(
            int fd,
            const std::shared_ptr<rawstor::ost::Context> &context,
            uint16_t cid,
            iovec *iov, unsigned int niov, size_t size):
            rawstor::io::TaskVector(fd),
            _context(context),
            _cid(cid),
            _iov(iov),
            _niov(niov),
            _size(size)
        {
            _context->add_read();
        }

        void operator()(RawstorIOEvent *event) {
            _context->sub_read();

            DriverOp &op = _context->find_op(_cid);
            op.response_body_cb(event);

            if (!_context->has_reads()) {
                _context->session().read_response_head(*rawstor::io_queue);
            }
        }

        iovec* iov() noexcept {
            return _iov;
        }

        unsigned int niov() const noexcept {
            return _niov;
        }

        size_t size() const noexcept {
            return _size;
        }
};


} // unnamed


namespace rawstor {
namespace ost {


void Context::register_op(const std::shared_ptr<DriverOp> &op) {
    _ops[op->cid()] = op;
}


void Context::fail_all(int error) {
    std::vector<std::shared_ptr<DriverOp>> inflight_ops;
    inflight_ops.reserve(_ops.size());
    for (const auto &i: _ops) {
        if (i.second->in_flight()) {
            inflight_ops.push_back(i.second);
        }
    }
    for (auto i: inflight_ops) {
        i->dispatch(0, error);
    }
}


Driver::Driver(const URI &uri, unsigned int depth):
    rawstor::Driver(uri, depth),
    _cid_counter(0),
    _object(nullptr),
    _context(std::make_shared<Context>(*this))
{
    int fd = _connect();
    set_fd(fd);
}


Driver::~Driver() {
    _context->detach();
}


int Driver::_connect() {
    if (!uri().path().str().empty() && uri().path().str() != "/") {
        std::ostringstream oss;
        oss << "Empty path expected: " << uri().str();
        throw std::runtime_error(oss.str());
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


void Driver::read_response_head(rawstor::io::Queue &queue) {
    std::unique_ptr<ResponseHead> res =
        std::make_unique<ResponseHead>(
            fd(), _context);
    queue.read(std::move(res));
}


void Driver::read_response_body(
    rawstor::io::Queue &queue, uint16_t cid,
    void *buf, size_t size)
{
    std::unique_ptr<ResponseBodyScalar> res =
        std::make_unique<ResponseBodyScalar>(
            fd(), _context, cid, buf, size);
    queue.read(std::move(res));
}


void Driver::read_response_body(
    rawstor::io::Queue &queue, uint16_t cid,
    iovec *iov, unsigned int niov, size_t size)
{
    std::unique_ptr<ResponseBodyVector> res =
        std::make_unique<ResponseBodyVector>(
            fd(), _context, cid, iov, niov, size);
    queue.read(std::move(res));
}


void Driver::create(
    rawstor::io::Queue &,
    const RawstorObjectSpec &, RawstorUUID *id,
    RawstorCallback *cb, void *data)
{
    /**
     * TODO: Implement me.
     */
    int res = rawstor_uuid7_init(id);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    cb(nullptr, 0, 0, 0, data);
}


void Driver::remove(
    rawstor::io::Queue &,
    const RawstorUUID &,
    RawstorCallback *, void *)
{
    throw std::runtime_error("Driver::remove() not implemented");
}


void Driver::spec(
    rawstor::io::Queue &,
    const RawstorUUID &, RawstorObjectSpec *sp,
    RawstorCallback *cb, void *data)
{
    rawstor_info("%s: Reading object specification...\n", str().c_str());

    /**
     * TODO: Implement me.
     */
    *sp = {
        .size = 1 << 30,
    };

    rawstor_info(
        "%s: Object specification successfully received (emulated)\n",
        str().c_str());

    cb(nullptr, 0, 0, 0, data);
}


void Driver::set_object(
    rawstor::io::Queue &queue,
    RawstorObject *object,
    RawstorCallback *cb, void *data)
{
    rawstor_info("%s: Setting object id\n", str().c_str());

    assert(_cid_counter == 0); // OST returns always 0.

    std::shared_ptr<DriverOpSetObjectId> op =
        std::make_shared<DriverOpSetObjectId>(
            _context, _cid_counter++, cb, data);
    _context->register_op(op);

    std::unique_ptr<RequestSetObjectId> req =
        std::make_unique<RequestSetObjectId>(
            fd(), op, object->id());
    queue.write(std::move(req));

    if (!_context->has_reads()) {
        read_response_head(queue);
    }

    _object = object;
}


void Driver::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::shared_ptr<DriverOpRead> op =
        std::make_shared<DriverOpRead>(
            _context, _cid_counter++, buf, size, cb, data);
    _context->register_op(op);

    std::unique_ptr<RequestCmdRead> req =
        std::make_unique<RequestCmdRead>(
            fd(), op, size, offset);
    io_queue->write(std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}


void Driver::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::shared_ptr<DriverOpReadV> op =
        std::make_shared<DriverOpReadV>(
            _context, _cid_counter++, iov, niov, size, cb, data);
    _context->register_op(op);

    std::unique_ptr<RequestCmdRead> req =
        std::make_unique<RequestCmdRead>(
            fd(), op, size, offset);
    io_queue->write(std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}


void Driver::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::shared_ptr<DriverOpWrite> op =
        std::make_shared<DriverOpWrite>(
            _context, _cid_counter++, size, cb, data);
    _context->register_op(op);

    std::unique_ptr<RequestCmdWrite> req =
        std::make_unique<RequestCmdWrite>(
            fd(), op, buf, size, offset);
    io_queue->write(std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}


void Driver::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::shared_ptr<DriverOpWrite> op =
        std::make_shared<DriverOpWrite>(
            _context, _cid_counter++, size, cb, data);
    _context->register_op(op);

    std::unique_ptr<RequestCmdWrite> req =
        std::make_unique<RequestCmdWrite>(
            fd(), op, iov, niov, size, offset);
    io_queue->write(std::move(req));

    if (!_context->has_reads()) {
        read_response_head(*io_queue);
    }
}


}} // rawstor::ost
