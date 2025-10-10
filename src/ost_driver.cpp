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
        "[%u] %s(): %zi of %zu\n", \
        cid, __FUNCTION__, \
        event->result(), \
        event->size())


namespace {


void validate_event(rawstor::ost::Driver &s, RawstorIOEvent *event) {
    int error = event->error();
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (event->result() != event->size()) {
        rawstor_error(
            "%s: Unexpected event size: %zu != %zu\n",
            s.str().c_str(),
            event->result(),
            event->size());
        RAWSTOR_THROW_SYSTEM_ERROR(EAGAIN);
    }
}


/*
void validate_response(
    rawstor::ost::Driver &s, const RawstorOSTFrameResponse &response)
{
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
*/


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


class DriverOp {
    private:
        static uint16_t _cid_counter;

        Driver *_s;
        uint16_t _cid;

    protected:
        bool _in_flight;
        rawstor::io::Queue *_q;
        RawstorCallback *_cb;
        void *_data;

        static int _request_cb(
            RawstorIOEvent *event, void *data) noexcept
        {
            DriverOp *op = static_cast<DriverOp*>(data);
            Driver &s = op->session();
            int error = 0;

            try {
                op_trace(op->_cid, event);

                validate_event(s, event);

                op->_in_flight = true;
            } catch (const std::system_error &e) {
                error = e.code().value();
            }

            int res = 0;
            if (error) {
                res = op->_cb(
                    s.object(),
                    event->size(), 0, error,
                    op->_data);
                delete op;
            }

            return res;
        }

    public:
        DriverOp(
            Driver &s, RawstorCallback *cb, void *data):
            _s(&s),
            _cid(++_cid_counter),
            _in_flight(false),
            _q(nullptr),
            _cb(cb),
            _data(data)
        {
            _s->register_request(*this);
        }

        DriverOp(const DriverOp &) = delete;
        DriverOp(DriverOp &&) = delete;
        virtual ~DriverOp() {
            if (_s != nullptr) {
                _s->unregister_request(*this);
            }
        }

        DriverOp& operator=(const DriverOp &) = delete;
        DriverOp& operator=(DriverOp &&) = delete;

        inline Driver& session() {
            if (_s == nullptr) {
                throw std::runtime_error("Driver operation detached");
            }
            return *_s;
        }

        inline rawstor::io::Queue& queue() {
            if (_q == nullptr) {
                throw std::runtime_error("Driver operation not submitted");
            }
            return *_q;
        }

        inline void detach() noexcept {
            _s = nullptr;
        }

        inline uint16_t cid() const noexcept {
            return _cid;
        }

        inline bool in_flight() const noexcept {
            return _in_flight;
        }

        virtual int dispatch(int res, int error) noexcept = 0;

        virtual void submit(rawstor::io::Queue &queue) = 0;
        virtual bool response_head_cb(
            RawstorIOEvent *event,
            RawstorOSTFrameResponse &response) = 0;
};


uint16_t DriverOp::_cid_counter = 0;


class DriverOpResponse {
    private:
        rawstor::ost::Driver *_s;
        RawstorOSTFrameResponse _response;

        rawstor::ost::Driver& session() {
            if (_s == nullptr) {
                throw std::runtime_error("Driver operation detached");
            }
            return *_s;
        }

        static int _submit_cb(RawstorIOEvent *, void *) noexcept {
            return 0;
        }

    public:
        DriverOpResponse(rawstor::ost::Driver &s): _s(&s) {}
        DriverOpResponse(const DriverOpResponse &) = delete;
        DriverOpResponse(DriverOpResponse &&) = delete;
        ~DriverOpResponse() {}
        DriverOpResponse& operator=(const DriverOpResponse &) = delete;
        DriverOpResponse& operator=(DriverOpResponse &&) = delete;

        void submit(rawstor::io::Queue &queue) {
            queue.read(
                session().fd(),
                &_response, sizeof(_response),
                _submit_cb, this);
        }
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


class DriverOpFrameBasic: public rawstor::ost::DriverOp {
    protected:
        RawstorOSTFrameBasic _request;

    public:
        DriverOpFrameBasic(
            rawstor::ost::Driver &s,
            const RawstorUUID &id,
            const RawstorOSTCommandType &cmd,
            RawstorCallback *cb, void *data):
            rawstor::ost::DriverOp(s, cb, data),
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

        void submit(rawstor::io::Queue &queue) {
            _q = &queue;
            queue.write(
                session().fd(),
                &_request, sizeof(_request),
                DriverOp::_request_cb, this);
        }
};


class DriverOpCmdSetObjectId final: public DriverOpFrameBasic {
    public:
        DriverOpCmdSetObjectId(
            rawstor::ost::Driver &s,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data):
            DriverOpFrameBasic(
                s,
                id, RAWSTOR_CMD_SET_OBJECT,
                cb, data)
        {}

        int dispatch(int res, int error) noexcept {
            return _cb(
                session().object(),
                0, res, error,
                _data);
        }

        bool response_head_cb(
            RawstorIOEvent *event, RawstorOSTFrameResponse &response)
        {
            op_trace(cid(), event);
            _in_flight = false;
            validate_cmd(session(), response.cmd, _request.cmd);

            return false;
        }
};


class DriverOpFrameIO: public rawstor::ost::DriverOp {
    protected:
        RawstorOSTFrameIO _request;

    public:
        DriverOpFrameIO(
            rawstor::ost::Driver &s,
            const RawstorOSTCommandType &cmd,
            size_t size, off_t offset, uint64_t hash,
            RawstorCallback *cb, void *data):
            rawstor::ost::DriverOp(s, cb, data),
            _request({
                .magic = RAWSTOR_MAGIC,
                .cmd = cmd,
                .cid = cid(),
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash,
                .sync = 0,
            })
        {}

        int dispatch(int res, int error) noexcept {
            return _cb(
                session().object(),
                _request.len, res, error,
                _data);
        }
};


class DriverOpCmdRead final: public DriverOpFrameIO {
    private:
        void *_buf;
        uint64_t _hash;
        int32_t _res;

        static int _response_body_cb(
            RawstorIOEvent *event, void *data) noexcept
        {
            DriverOpCmdRead *op = static_cast<DriverOpCmdRead*>(data);
            rawstor::ost::Driver &s = op->session();
            int error = 0;

            try {
                op_trace(op->cid(), event);
                validate_event(s, event);

                uint64_t hash = rawstor_hash_scalar(
                    op->_buf, op->_request.len);
                validate_hash(s, op->_hash, hash);
            } catch (const std::system_error &e) {
                error = e.code().value();
            }

            int res = op->dispatch(op->_res, error);
            delete op;

            return res;
        }

    public:
        DriverOpCmdRead(
            rawstor::ost::Driver &s,
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            DriverOpFrameIO(
                s,
                RAWSTOR_CMD_READ,
                size, offset, 0,
                cb, data),
            _buf(buf),
            _hash(0)
        {}

        void submit(rawstor::io::Queue &queue) {
            _q = &queue;
            queue.write(
                session().fd(),
                &_request, sizeof(_request),
                DriverOp::_request_cb, this);
        }

        bool response_head_cb(
            RawstorIOEvent *event, RawstorOSTFrameResponse &response)
        {
            op_trace(cid(), event);
            _in_flight = false;
            validate_cmd(session(), response.cmd, _request.cmd);

            _hash = response.hash;
            _res = response.res;

            event->queue().read(
                session().fd(),
                _buf, _request.len,
                _response_body_cb, this);

            return true;
        }
};


class DriverOpCmdReadV final: public DriverOpFrameIO {
    private:
        iovec *_iov;
        unsigned int _niov;
        uint64_t _hash;
        int32_t _res;

        static int _response_body_cb(
            RawstorIOEvent *event, void *data) noexcept
        {
            DriverOpCmdReadV *op = static_cast<DriverOpCmdReadV*>(data);
            rawstor::ost::Driver &s = op->session();
            int error = 0;

            try {
                op_trace(op->cid(), event);
                validate_event(s, event);

                uint64_t hash;
                int res = rawstor_hash_vector(op->_iov, op->_niov, &hash);
                if (res < 0) {
                    RAWSTOR_THROW_SYSTEM_ERROR(-res);
                }
                validate_hash(s, op->_hash, hash);
            } catch (const std::system_error &e) {
                error = e.code().value();
            }

            int res = op->dispatch(op->_res, error);
            delete op;

            return res;
        }

    public:
        DriverOpCmdReadV(
            rawstor::ost::Driver &s,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            DriverOpFrameIO(
                s,
                RAWSTOR_CMD_READ,
                size, offset, 0,
                cb, data),
            _iov(iov),
            _niov(niov)
        {}

        void submit(rawstor::io::Queue &queue) {
            _q = &queue;
            queue.write(
                session().fd(),
                &_request, sizeof(_request),
                DriverOp::_request_cb, this);
        }

        bool response_head_cb(
            RawstorIOEvent *event, RawstorOSTFrameResponse &response)
        {
            op_trace(cid(), event);
            _in_flight = false;
            validate_cmd(session(), response.cmd, _request.cmd);

            event->queue().readv(
                session().fd(),
                _iov, _niov, _request.len,
                _response_body_cb, this);

            return true;
        }
};


class DriverOpCmdWrite final: public DriverOpFrameIO {
    private:
        std::vector<iovec> _iov;

    public:
        DriverOpCmdWrite(
            rawstor::ost::Driver &s,
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            DriverOpFrameIO(
                s,
                RAWSTOR_CMD_WRITE,
                size, offset, hash(buf, size),
                cb, data)
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

        void submit(rawstor::io::Queue &queue) {
            _q = &queue;
            queue.writev(
                session().fd(),
                _iov.data(), _iov.size(), sizeof(_request) + _request.len,
                DriverOp::_request_cb, this);
        }

        bool response_head_cb(
            RawstorIOEvent *event, RawstorOSTFrameResponse &response)
        {
            op_trace(cid(), event);
            _in_flight = false;
            validate_cmd(session(), response.cmd, _request.cmd);

            return false;
        }
};


class DriverOpCmdWriteV final: public DriverOpFrameIO {
    private:
        std::vector<iovec> _iov;

    public:
        DriverOpCmdWriteV(
            rawstor::ost::Driver &s,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            DriverOpFrameIO(
                s,
                RAWSTOR_CMD_WRITE,
                size, offset, hash(iov, niov),
                cb, data)
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

        void submit(rawstor::io::Queue &queue) {
            _q = &queue;
            queue.writev(
                session().fd(),
                _iov.data(), _iov.size(), sizeof(_request) + _request.len,
                DriverOp::_request_cb, this);
        }

        bool response_head_cb(
            RawstorIOEvent *event, RawstorOSTFrameResponse &response)
        {
            op_trace(cid(), event);
            _in_flight = false;
            validate_cmd(session(), response.cmd, _request.cmd);

            return false;
        }
};


} // unnamed


namespace rawstor {
namespace ost {


Driver::Driver(const URI &uri, unsigned int depth):
    rawstor::Driver(uri, depth),
    _object(nullptr),
    _op_response(nullptr)
{
    int fd = _connect();
    set_fd(fd);
}


Driver::~Driver() {
    /**
     * TODO: Probably should be rewritten
     * with detach() call to inflight requests.
     */
    while (!_ops.empty()) {
        delete _ops.begin()->second;
    }
}


void Driver::register_request(DriverOp &op) {
    if (_ops.empty()) {
        _read_response_head(op.queue());
    }
    _ops[op.cid()] = &op;
}


void Driver::unregister_request(DriverOp &op) {
    _ops.erase(op.cid());
    if (!_ops.empty()) {
        _read_response_head(op.queue());
    }
}


DriverOp* Driver::_find_op(uint16_t cid) {
    std::unordered_map<uint16_t, DriverOp*>::iterator it = _ops.find(cid);
    if (it == _ops.end()) {
        rawstor_error("Unexpected cid: %u\n", cid);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    return it->second;
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


void Driver::_read_response_head(rawstor::io::Queue &queue) {
    std::unique_ptr<DriverOpResponse> response =
        std::make_unique<DriverOpResponse>(*this);
    response->submit(queue);
    response.release();
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

    std::unique_ptr<DriverOpCmdSetObjectId> op =
        std::make_unique<DriverOpCmdSetObjectId>(*this, object->id(), cb, data);

    op->submit(queue);

    op.release();

    _object = object;
}


void Driver::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::unique_ptr<DriverOpCmdRead> op = std::make_unique<DriverOpCmdRead>(
        *this, buf, size, offset, cb, data);

    op->submit(*io_queue);

    op.release();
}


void Driver::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::unique_ptr<DriverOpCmdReadV> op = std::make_unique<DriverOpCmdReadV>(
        *this, iov, niov, size, offset, cb, data);

    op->submit(*io_queue);

    op.release();
}


void Driver::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    std::unique_ptr<DriverOpCmdWrite> op = std::make_unique<DriverOpCmdWrite>(
        *this, buf, size, offset, cb, data);

    op->submit(*io_queue);

    op.release();
}


void Driver::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    std::unique_ptr<DriverOpCmdWriteV> op = std::make_unique<DriverOpCmdWriteV>(
        *this, iov, niov, size, offset, cb, data);

    op->submit(*io_queue);

    op.release();
}


}} // rawstor::ost
