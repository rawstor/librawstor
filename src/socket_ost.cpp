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
        RAWSTOR_THROW_ERRNO(error);
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_error(
            "Partial event: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        RAWSTOR_THROW_ERRNO(EIO);
    }
}


inline void validate_response(const RawstorOSTFrameResponse &response) {
    if (response.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "FATAL! Frame with wrong magic number: %x != %x\n",
            response.magic, RAWSTOR_MAGIC);
        RAWSTOR_THROW_ERRNO(EIO);
    }

    if (response.res < 0) {
        rawstor_error(
            "Server error: %s\n",
            strerror(-response.res));
        RAWSTOR_THROW_ERRNO(EPROTO);
    }
}


inline void validate_cmd(
    enum RawstorOSTCommandType cmd, enum RawstorOSTCommandType expected)
{
    if (cmd != expected) {
        rawstor_error("Unexpected command in response: %d\n", cmd);
        RAWSTOR_THROW_ERRNO(EPROTO);
    }
}


} // unnamed


namespace rawstor {


struct SocketOp {
    rawstor::Socket *s;

    uint16_t cid;
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

    void (*next)(RawstorIOQueue *queue, SocketOp *op);

    iovec iov[IOVEC_SIZE];
    unsigned int niov;
    size_t size;

    RawstorCallback *callback;
    void *data;
};


Socket::Socket(const RawstorSocketAddress &ost, unsigned int depth):
    _fd(-1),
    _object(nullptr),
    _ops_array(),
    _ops(nullptr)
{
    _fd = _connect(ost);

    try {
        _ops = rawstor_ringbuf_create(depth, sizeof(SocketOp*));
        if (_ops == nullptr) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        _ops_array.reserve(depth);
        for (unsigned int i = 0; i < depth; ++i) {
            SocketOp *op = new SocketOp();
            op->cid = i + 1;

            _ops_array.push_back(op);

            SocketOp **it = static_cast<SocketOp**>(rawstor_ringbuf_head(_ops));
            assert(rawstor_ringbuf_push(_ops) == 0);
            *it = op;
        }
    } catch (...) {
        for (SocketOp *op: _ops_array) {
            delete op;
        }
        rawstor_ringbuf_delete(_ops);

        if (::close(_fd) == -1) {
            rawstor_error(
                "Socket::Socket(): close failed: %s\n", strerror(errno));
        }
        _fd = -1;

        throw;
    }
}


Socket::Socket(Socket &&other) noexcept:
    _fd(std::exchange(other._fd, -1)),
    _object(std::exchange(other._object, nullptr)),
    _ops_array(std::move(other._ops_array)),
    _ops(std::exchange(other._ops, nullptr)),
    _response(std::move(other._response))
{
    for (SocketOp *op: _ops_array) {
        op->s = this;
    }
}


Socket::~Socket() {
    if (_fd != -1) {
        if (::close(_fd) == -1) {
            rawstor_error(
                "Socket::~Socket(): close failed: %s\n", strerror(errno));
        }
    }

    for (SocketOp *op: _ops_array) {
        delete op;
    }

    if (_ops != nullptr) {
        rawstor_ringbuf_delete(_ops);
    }
}


SocketOp* Socket::_acquire_op() {
    SocketOp **it = static_cast<SocketOp**>(rawstor_ringbuf_tail(_ops));
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    return *it;
}


void Socket::_release_op(SocketOp *op) noexcept {
    SocketOp **it = static_cast<SocketOp**>(rawstor_ringbuf_head(_ops));
    assert(rawstor_ringbuf_push(_ops) == 0);
    *it = op;
}


SocketOp* Socket::_find_op(unsigned int cid) {
    if (cid < 1 || cid > _ops_array.size()) {
        rawstor_error("Unexpected cid in response: %u\n", cid);
        RAWSTOR_THROW_ERRNO(EIO);
    }

    return _ops_array[cid - 1];
}


int Socket::_connect(const RawstorSocketAddress &ost) {
    int res;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    try {
        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            res = rawstor_socket_set_snd_timeout(fd, so_sndtimeo);
            if (res < 0) {
                RAWSTOR_THROW_ERRNO(-res);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            res = rawstor_socket_set_rcv_timeout(fd, so_rcvtimeo);
            if (res < 0) {
                RAWSTOR_THROW_ERRNO(-res);
            }
        }

        unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
        if (tcp_user_timeo != 0) {
            res = rawstor_socket_set_user_timeout(fd, tcp_user_timeo);
            if (res < 0) {
                RAWSTOR_THROW_ERRNO(-res);
            }
        }

        sockaddr_in servaddr = {};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(ost.port);

        res = inet_pton(AF_INET, ost.host, &servaddr.sin_addr);
        if (res == 0) {
            RAWSTOR_THROW_ERRNO(EINVAL);
        } else if (res == -1) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        rawstor_info("Connecting to %s:%u\n", ost.host, ost.port);
        if (connect(fd, (sockaddr*)&servaddr, sizeof(servaddr)) == -1) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        res = rawstor_io_queue_setup_fd(fd);
        if (res < 0) {
            RAWSTOR_THROW_ERRNO(-res);
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
        RAWSTOR_THROW_ERRNO(-res);
    }
}


void Socket::_read_response_set_object_id(RawstorIOQueue *queue, SocketOp *op) {
    int res = rawstor_io_queue_read(
        queue, _fd,
        &_response, sizeof(_response),
        _read_response_set_object_id_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(-res);
    }
}


void Socket::_read_response_head(RawstorIOQueue *queue) {
    int res = rawstor_io_queue_read(
        queue, _fd,
        &_response, sizeof(_response),
        _read_response_head_cb, this);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(-res);
    }
}


void Socket::_read_response_body(RawstorIOQueue *queue, SocketOp *op) {
    int res = rawstor_io_queue_read(
        queue, _fd,
        op->payload.linear.data, op->request.io.len,
        _read_response_body_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(-res);
    }
}


void Socket::_readv_response_body(RawstorIOQueue *queue, SocketOp *op) {
    int res = rawstor_io_queue_readv(
        queue, _fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request.io.len,
        _readv_response_body_cb, op);
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(-res);
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
    int ret = 0;

    try {
        op_trace(op->cid, event);

        ::validate_event(event);

        RawstorOSTFrameResponse &response = s->_response;

        ::validate_response(response);

        validate_cmd(response.cmd, RAWSTOR_CMD_SET_OBJECT);

        int res = op->callback(
            s->_object->c_ptr(),
            0, 0, 0,
            op->data);
        if (res < 0) {
            RAWSTOR_THROW_ERRNO(-res);
        }

        s->_read_response_head(rawstor_io_queue);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    s->_release_op(op);

    return ret;
}


int Socket::_read_response_head_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    int res;
    Socket *s = static_cast<Socket*>(data);

    try {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        ::validate_event(event);

        RawstorOSTFrameResponse &response = s->_response;
        ::validate_response(s->_response);

        SocketOp *op = s->_find_op(response.cid);
        op_trace(op->cid, event);

        try {
            validate_cmd(s->_response.cmd, op->request.io.cmd);

            if (op->next != nullptr) {
                op->next(rawstor_io_event_queue(event), op);
            } else {
                s->_read_response_head(rawstor_io_event_queue(event));

                res = op->callback(
                    s->_object->c_ptr(),
                    op->request.io.len, op->request.io.len, 0,
                    op->data);
                if (res < 0) {
                    RAWSTOR_THROW_ERRNO(-res);
                }

                s->_release_op(op);
            }
        } catch (...) {
            s->_release_op(op);
            throw;
        }
    } catch (const std::system_error &e) {
        return -e.code().value();
    }

    return 0;
}


int Socket::_read_response_body_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    /**
     * FIXME: Proper error handling.
     */

    SocketOp *op = static_cast<SocketOp*>(data);
    Socket *s = op->s;
    int ret = 0;

    try {
        op_trace(op->cid, event);

        ::validate_event(event);

        uint64_t hash = rawstor_hash_scalar(
            op->payload.linear.data, op->request.io.len);

        if (s->_response.hash != hash) {
            rawstor_error(
                "Response hash mismatch: %llx != %llx\n",
                (unsigned long long)s->_response.hash,
                (unsigned long long)hash);
            RAWSTOR_THROW_ERRNO(EIO);
        }

        s->_read_response_head(rawstor_io_event_queue(event));

        ret = op->callback(
            s->_object->c_ptr(),
            op->request.io.len, op->request.io.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    s->_release_op(op);

    return ret;
}


int Socket::_readv_response_body_cb(
    RawstorIOEvent *event, void *data) noexcept
{
    int res;
    SocketOp *op = static_cast<SocketOp*>(data);
    Socket *s = op->s;
    int ret = 0;

    try {
        op_trace(op->cid, event);

        ::validate_event(event);

        uint64_t hash;
        res = rawstor_hash_vector(
            op->payload.vector.iov, op->payload.vector.niov, &hash);
        if (res < 0) {
            RAWSTOR_THROW_ERRNO(-res);
        }

        if (s->_response.hash != hash) {
            rawstor_error(
                "Response hash mismatch: %llx != %llx\n",
                (unsigned long long)s->_response.hash,
                (unsigned long long)hash);
            RAWSTOR_THROW_ERRNO(EIO);
        }

        s->_read_response_head(rawstor_io_event_queue(event));

        ret = op->callback(
            s->_object->c_ptr(),
            op->request.io.len, op->request.io.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    s->_release_op(op);

    return ret;
}


const char* Socket::engine_name() noexcept {
    return "ost";
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
        RAWSTOR_THROW_ERRNO(-res);
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
    /**
     * TODO: Implement me.
     */

    *sp = {
        .size = 1 << 30,
    };

    cb(nullptr, 0, 0, 0, data);
}


void Socket::set_object(
    RawstorIOQueue *queue,
    rawstor::Object *object,
    RawstorCallback *cb, void *data)
{
    rawstor_debug("%s(): set object id\n", __FUNCTION__);

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
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
            .next = nullptr,
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
            .next = _next_read_response_body,
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
            .next = _next_readv_response_body,
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
            .next = nullptr,
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
        RAWSTOR_THROW_ERRNO(-res);
    }

    if (niov >= IOVEC_SIZE) {
        throw std::runtime_error("Large iovecs not supported");
    }

    SocketOp *op = _acquire_op();

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
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
            .next = nullptr,
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
