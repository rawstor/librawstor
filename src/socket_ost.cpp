#include "socket_ost.hpp"

#include "object.hpp"
#include "opts.h"
#include "ost_protocol.h"
#include "rawstor_internals.h"

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstor/object.h>

#include <arpa/inet.h>

#include <algorithm>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <utility>

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256


#define op_trace(cid, event) \
    rawstor_debug( \
        "[%u] %s(): %zi of %zu\n", \
        cid, __FUNCTION__, \
        rawstor_io_event_result(event), \
        rawstor_io_event_size(event))


namespace {


inline void validate_event(RawstorIOEvent *event) {
    int error = rawstor_io_event_error(event);
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_error(
            "Unexpected event size: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        RAWSTOR_THROW_SYSTEM_ERROR(EAGAIN);
    }
}


inline void validate_response(const RawstorOSTFrameResponse &response) {
    if (response.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "Unexpected magic number: %x != %x\n",
            response.magic, RAWSTOR_MAGIC);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }

    if (response.res < 0) {
        rawstor_error(
            "Server error: %s\n",
            strerror(-response.res));
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }
}


inline void validate_cmd(
    enum RawstorOSTCommandType cmd, enum RawstorOSTCommandType expected)
{
    if (cmd != expected) {
        rawstor_error("Unexpected command: %d\n", cmd);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }
}


inline void validate_hash(uint64_t hash, uint64_t expected) {
    if (hash != expected) {
        rawstor_error(
            "Hash mismatch: %llx != %llx\n",
            (unsigned long long)hash,
            (unsigned long long)expected);
        RAWSTOR_THROW_SYSTEM_ERROR(EPROTO);
    }
}


} // unnamed


namespace rawstor {


struct SocketOp {
    rawstor::Socket *s;

    uint16_t cid;
    int flight;
    void (*next)(RawstorIOQueue *queue, SocketOp *op);

    union {
        RawstorOSTFrameBasic basic;
        RawstorOSTFrameIO io;
    } request;

    union {
        struct {
            void *data;
        } linear;
        struct {
            iovec *iov;
            unsigned int niov;
        } vector;
    } payload;

    iovec iov[IOVEC_SIZE];
    unsigned int niov;
    size_t size;

    RawstorCallback *callback;
    void *data;
};


Socket::Socket(const SocketAddress &ost, unsigned int depth):
    _ost(ost),
    _fd(-1),
    _object(nullptr),
    _ops_array(),
    _ops(depth)
{
    _fd = _connect();

    try {
        _ops_array.reserve(depth);
        for (unsigned int i = 0; i < depth; ++i) {
            SocketOp *op = new SocketOp();
            op->cid = i + 1;

            _ops_array.push_back(op);

            _ops.push(op);
        }
    } catch (...) {
        for (SocketOp *op: _ops_array) {
            delete op;
        }

        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Socket::Socket(): close failed: %s\n", strerror(error));
        }
        _fd = -1;

        throw;
    }
}


Socket::Socket(Socket &&other) noexcept:
    _ost(std::move(other._ost)),
    _fd(std::exchange(other._fd, -1)),
    _object(std::exchange(other._object, nullptr)),
    _ops_array(std::move(other._ops_array)),
    _ops(std::move(other._ops)),
    _response(std::move(other._response))
{
    for (SocketOp *op: _ops_array) {
        op->s = this;
    }
}


Socket::~Socket() {
    if (_fd != -1) {
        if (::close(_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Socket::~Socket(): close failed: %s\n", strerror(error));
        }
        rawstor_info("fd %d: Socket closed\n", _fd);
    }

    for (SocketOp *op: _ops_array) {
        delete op;
    }
}


SocketOp* Socket::_acquire_op() {
    return _ops.pop();
}


void Socket::_release_op(SocketOp *op) noexcept {
    assert(_ops.size() < _ops.capacity());

    _ops.push(op);
}


SocketOp* Socket::_find_op(unsigned int cid) {
    if (cid < 1 || cid > _ops_array.size()) {
        rawstor_error("Unexpected cid: %u\n", cid);
        RAWSTOR_THROW_SYSTEM_ERROR(EIO);
    }

    return _ops_array[cid - 1];
}


int Socket::_connect() {
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
        servaddr.sin_port = htons(_ost.port());

        res = inet_pton(AF_INET, _ost.host().c_str(), &servaddr.sin_addr);
        if (res == 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTOR_THROW_ERRNO();
        }

        rawstor_info(
            "fd %d: Connecting to %s:%u...\n",
            fd, _ost.host().c_str(), _ost.port());
        if (connect(fd, (sockaddr*)&servaddr, sizeof(servaddr)) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
        rawstor_info("fd %d: Connected\n", fd);

        res = rawstor_io_queue_setup_fd(fd);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    } catch (...) {
        ::close(fd);
        throw;
    }

    return fd;
}


void Socket::_writev_request(RawstorIOQueue *queue, SocketOp *op) {
    int res = rawstor_io_queue_writev(
        queue, _fd,
        op->iov, op->niov, op->size,
        _writev_request_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


void Socket::_read_response_set_object_id(
    RawstorIOQueue *queue, SocketOp *op)
{
    int res = rawstor_io_queue_read(
        queue, _fd,
        &_response, sizeof(_response),
        _read_response_set_object_id_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


void Socket::_read_response_head(RawstorIOQueue *queue) {
    int res = rawstor_io_queue_read(
        queue, _fd,
        &_response, sizeof(_response),
        _read_response_head_cb, this);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


void Socket::_read_response_body(RawstorIOQueue *queue, SocketOp *op) {
    int res = rawstor_io_queue_read(
        queue, _fd,
        op->payload.linear.data, op->request.io.len,
        _read_response_body_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


void Socket::_readv_response_body(RawstorIOQueue *queue, SocketOp *op) {
    int res = rawstor_io_queue_readv(
        queue, _fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request.io.len,
        _readv_response_body_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


void Socket::_next_read_response_body(
    RawstorIOQueue *queue, SocketOp *op)
{
    op->s->_read_response_body(queue, op);
}


void Socket::_next_readv_response_body(
    RawstorIOQueue *queue, SocketOp *op)
{
    op->s->_readv_response_body(queue, op);
}


int Socket::_writev_request_cb(RawstorIOEvent *event, void *data) noexcept {
    SocketOp *op = static_cast<SocketOp*>(data);

    try {
        op_trace(op->cid, event);

        ::validate_event(event);

        op->flight = 1;

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int Socket::_read_response_set_object_id_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    SocketOp *op = static_cast<SocketOp*>(data);
    Socket *s = op->s;
    int error = 0;

    try {
        op_trace(op->cid, event);
        op->flight = 0;

        ::validate_event(event);

        RawstorOSTFrameResponse &response = s->_response;

        ::validate_response(response);

        ::validate_cmd(response.cmd, RAWSTOR_CMD_SET_OBJECT);
    } catch (const std::system_error &e) {
        error = e.code().value();
    }

    SocketOp op_copy = *op;
    s->_release_op(op);
    int res = op_copy.callback(
        s->_object->c_ptr(),
        0, 0, error,
        op_copy.data);

    if (!error && res == 0) {
        rawstor_info("fd %d: Object id successfully set\n", s->_fd);
        try {
            s->_read_response_head(rawstor_io_queue);
        } catch (const std::system_error &e) {
            return -e.code().value();
        }
    }

    return res;
}


int Socket::_read_response_head_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    Socket *s = static_cast<Socket*>(data);
    SocketOp *op = nullptr;
    int error = 0;

    try {
        ::validate_event(event);

        ::validate_response(s->_response);

        op = s->_find_op(s->_response.cid);
        op_trace(op->cid, event);
        op->flight = 0;

        ::validate_cmd(s->_response.cmd, op->request.io.cmd);
    } catch (const std::system_error &e) {
        error = e.code().value();
    }

    int res = 0;
    if (op != nullptr) {
        if (!error && op->next != nullptr) {
            try {
                op->next(rawstor_io_event_queue(event), op);
            } catch (const std::system_error &e) {
                error = e.code().value();
            }
        } else {
            SocketOp op_copy = *op;
            s->_release_op(op);
            res = op_copy.callback(
                s->_object->c_ptr(),
                op_copy.request.io.len, s->_response.res, error,
                op_copy.data);
            if (res == 0) {
                try {
                    s->_read_response_head(rawstor_io_event_queue(event));
                } catch (const std::system_error &e) {
                    return -e.code().value();
                }
            }
        }
    } else {
        std::vector<SocketOp*> ops_array(s->_ops_array.size());
        ops_array.resize(std::distance(
            ops_array.begin(),
            std::copy_if(
                s->_ops_array.begin(),
                s->_ops_array.end(),
                ops_array.begin(),
                [](SocketOp *op){return !op->flight;}
            )
        ));

        for (SocketOp *op: ops_array) {
            op->flight = 0;
            SocketOp op_copy = *op;
            s->_release_op(op);
            res = op_copy.callback(
                s->_object->c_ptr(),
                op_copy.request.io.len, 0, error,
                op_copy.data);
            if (res) {
                return res;
            }
        }
    }

    return res;
}


int Socket::_read_response_body_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    SocketOp *op = static_cast<SocketOp*>(data);
    Socket *s = op->s;
    int error = 0;

    try {
        op_trace(op->cid, event);

        ::validate_event(event);

        uint64_t hash = rawstor_hash_scalar(
            op->payload.linear.data, op->request.io.len);

        ::validate_hash(s->_response.hash, hash);
    } catch (const std::system_error &e) {
        error = e.code().value();
    }

    SocketOp op_copy = *op;
    s->_release_op(op);
    int res = op_copy.callback(
        s->_object->c_ptr(),
        op_copy.request.io.len, s->_response.res, error,
        op_copy.data);

    if (!error && res == 0) {
        try {
            s->_read_response_head(rawstor_io_event_queue(event));
        } catch (const std::system_error &e) {
            return -e.code().value();
        }
    }

    return res;
}


int Socket::_readv_response_body_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    SocketOp *op = static_cast<SocketOp*>(data);
    Socket *s = op->s;
    int error = 0;

    try {
        op_trace(op->cid, event);

        ::validate_event(event);

        uint64_t hash;
        int res = rawstor_hash_vector(
            op->payload.vector.iov, op->payload.vector.niov, &hash);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        ::validate_hash(s->_response.hash, hash);

    } catch (const std::system_error &e) {
        error = e.code().value();
    }

    SocketOp op_copy = *op;
    s->_release_op(op);
    int res = op_copy.callback(
        s->_object->c_ptr(),
        op_copy.request.io.len, s->_response.res, error,
        op_copy.data);

    if (!error && res == 0) {
        try {
            s->_read_response_head(rawstor_io_event_queue(event));
        } catch (const std::system_error &e) {
            return -e.code().value();
        }
    }

    return res;
}


const char* Socket::engine_name() noexcept {
    return "ost";
}


const SocketAddress& Socket::ost() const noexcept {
    return _ost;
}


void Socket::create(
    RawstorIOQueue *,
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


void Socket::remove(
    RawstorIOQueue *,
    const RawstorUUID &,
    RawstorCallback *, void *)
{
    throw std::runtime_error("Socket::remove() not implemented");
}


void Socket::spec(
    RawstorIOQueue *,
    const RawstorUUID &, RawstorObjectSpec *sp,
    RawstorCallback *cb, void *data)
{
    rawstor_info("fd %d: Reading object specification...\n", _fd);

    /**
     * TODO: Implement me.
     */
    *sp = {
        .size = 1 << 30,
    };

    rawstor_info(
        "fd %d: Object specification successfully received(emulated)\n", _fd);

    cb(nullptr, 0, 0, 0, data);
}


void Socket::set_object(
    RawstorIOQueue *queue,
    rawstor::Object *object,
    RawstorCallback *cb, void *data)
{
    rawstor_info("fd %d: Setting object id\n", _fd);

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .flight = 0,
            .next = nullptr,
            .request = {
                .basic = {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SET_OBJECT,
                    .obj_id = {},
                    .offset = 0,
                    .val = 0,
                },
            },
            .payload = {},
            .iov = {},
            .niov = 0,
            .size = 0,
            .callback = cb,
            .data = data,
        };

        memcpy(
            op->request.basic.obj_id,
            object->id().bytes, sizeof(op->request.basic.obj_id));

        op->iov[0] = {
            .iov_base = &op->request.basic,
            .iov_len = sizeof(op->request.basic),
        };
        op->niov = 1;
        op->size = sizeof(op->request.basic);

        _writev_request(queue, op);

        _read_response_set_object_id(queue, op);
    } catch (...) {
        _release_op(op);
        throw;
    }

    _object = object;
}


void Socket::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .flight = 0,
            .next = _next_read_response_body,
            .request = {
                .io = {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = op->cid,
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)size,
                    .hash = 0,
                    .sync = 0,
                },
            },
            .payload = {
                .linear = {
                    .data = buf,
                },
            },
            .iov = {},
            .niov = 0,
            .size = 0,
            .callback = cb,
            .data = data,
        };

        op->iov[0] = {
            .iov_base = &op->request.io,
            .iov_len = sizeof(op->request.io),
        };
        op->niov = 1;
        op->size = sizeof(op->request.io);

        _writev_request(rawstor_io_queue, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Socket::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .flight = 0,
            .next = _next_readv_response_body,
            .request = {
                .io = {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = op->cid,
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)size,
                    .hash = 0,
                    .sync = 0,
                },
            },
            .payload = {
                .vector = {
                    .iov = iov,
                    .niov = niov,
                },
            },
            .iov = {},
            .niov = 0,
            .size = 0,
            .callback = cb,
            .data = data,
        };

        op->iov[0] = {
            .iov_base = &op->request.io,
            .iov_len = sizeof(op->request.io),
        };
        op->niov = 1;
        op->size = sizeof(op->request.io);

        _writev_request(rawstor_io_queue, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Socket::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .flight = 0,
            .next = nullptr,
            .request = {
                .io = {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = op->cid,
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)size,
                    .hash = rawstor_hash_scalar(buf, size),
                    .sync = 0,
                },
            },
            .payload = {
                .linear = {
                    .data = buf,
                },
            },
            .iov = {},
            .niov = 0,
            .size = 0,
            .callback = cb,
            .data = data,
        };

        op->iov[0] = {
            .iov_base = &op->request.io,
            .iov_len = sizeof(op->request.io),
        };
        op->iov[1] = {
            .iov_base = buf,
            .iov_len = size,
        };
        op->niov = 2;
        op->size = sizeof(op->request.io) + size;

        _writev_request(rawstor_io_queue, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Socket::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    uint64_t hash;
    int res = rawstor_hash_vector(iov, niov, &hash);
    if (res < 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    if (niov >= IOVEC_SIZE) {
        throw std::runtime_error("Large iovecs not supported");
    }

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .flight = 0,
            .next = nullptr,
            .request = {
                .io = {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = op->cid,
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)size,
                    .hash = hash,
                    .sync = 0,
                },
            },
            .payload = {
                .vector = {
                    .iov = iov,
                    .niov = niov,
                },
            },
            .iov = {},
            .niov = 0,
            .size = 0,
            .callback = cb,
            .data = data,
        };

        op->iov[0] = {
            .iov_base = &op->request.io,
            .iov_len = sizeof(op->request.io),
        };
        for (unsigned int i = 0; i < niov; ++i) {
            op->iov[i + 1] = iov[i];
        }
        op->niov = niov + 1;
        op->size = sizeof(op->request.io) + size;

        _writev_request(rawstor_io_queue, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


} // rawstor
