#include "socket_ost.hpp"

#include "object_ost.hpp"
#include "opts.h"
#include "ost_protocol.h"

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


namespace rawstor {


struct SocketOp {
    rawstor::Socket *s;

    uint16_t cid;
    RawstorOSTFrameIO request_frame;

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

    int (*process)(SocketOp *op, int fd);

    RawstorCallback *callback;

    void *data;
};


Socket::Socket(Connection &cn):
    _cn(cn),
    _object(nullptr),
    _fd(-1),
    _response_loop(0),
    _ops_array(),
    _ops(nullptr)
{
    try {
        _ops = rawstor_ringbuf_create(_cn.depth(), sizeof(SocketOp*));
        if (_ops == nullptr) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        _ops_array.reserve(_cn.depth());
        for (unsigned int i = 0; i < _cn.depth(); ++i) {
            SocketOp *op = new SocketOp();
            op->cid = i + 1;

            _ops_array.push_back(op);

            SocketOp **it = (SocketOp**)rawstor_ringbuf_head(_ops);
            assert(rawstor_ringbuf_push(_ops) == 0);
            *it = op;
        }
    } catch (...) {
        for (
            std::vector<SocketOp*>::iterator it = _ops_array.begin();
            it != _ops_array.end();
            ++it)
        {
            delete *it;
        }
        rawstor_ringbuf_delete(_ops);
        throw;
    }
}


Socket::Socket(Socket &&other):
    _cn(other._cn),
    _object(std::exchange(other._object, nullptr)),
    _fd(std::exchange(other._fd, -1)),
    _response_loop(std::exchange(other._response_loop, 0)),
    _ops_array(std::move(other._ops_array)),
    _ops(std::exchange(other._ops, nullptr)),
    _response_frame(std::move(other._response_frame))
{
    for (SocketOp *op: _ops_array) {
        op->s = this;
    }
}


Socket::~Socket() {
    if (_fd != -1) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Socket::close(): %s\n", e.what());
        }
    }

    for (SocketOp *op: _ops_array) {
        delete op;
    }

    rawstor_ringbuf_delete(_ops);
}


int Socket::_connect(const RawstorSocketAddress &ost) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    try {
        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            if (rawstor_socket_set_snd_timeout(fd, so_sndtimeo)) {
                RAWSTOR_THROW_ERRNO(errno);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            if (rawstor_socket_set_rcv_timeout(fd, so_rcvtimeo)) {
                RAWSTOR_THROW_ERRNO(errno);
            }
        }

        unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
        if (tcp_user_timeo != 0) {
            if (rawstor_socket_set_user_timeout(fd, tcp_user_timeo)) {
                RAWSTOR_THROW_ERRNO(errno);
            }
        }

        sockaddr_in servaddr = {};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(ost.port);

        int res = inet_pton(AF_INET, ost.host, &servaddr.sin_addr);
        if (res == 0) {
            RAWSTOR_THROW_ERRNO(EINVAL);
        }
        if (res < 0) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        rawstor_info("Connecting to %s:%u\n", ost.host, ost.port);
        if (connect(fd, (sockaddr*)&servaddr, sizeof(servaddr))) {
            RAWSTOR_THROW_ERRNO(errno);
        }

    } catch (...) {
        ::close(fd);
        throw;
    }

    return fd;
}


/**
 * TODO: Do it async or solve partial IO issue.
 */
void Socket::_set_object_id(int fd, const RawstorUUID &id) {
    RawstorOSTFrameBasic request_frame = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
        .obj_id = {},
        .offset = 0,
        .val = 0,
    };
    memcpy(request_frame.obj_id, id.bytes, sizeof(request_frame.obj_id));

    int res = write(fd, &request_frame, sizeof(request_frame));
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(errno);
    }
    assert(res == sizeof(request_frame));

    RawstorOSTFrameResponse response_frame;
    res = read(fd, &response_frame, sizeof(response_frame));
    if (res < 0) {
        RAWSTOR_THROW_ERRNO(errno);
    }
    assert(res == sizeof(response_frame));

    if (response_frame.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "Unexpected magic number: %x != %x\n",
            response_frame.magic, RAWSTOR_MAGIC);
        RAWSTOR_THROW_ERRNO(EPROTO);
    }

    if (response_frame.res < 0) {
        rawstor_error(
            "Server failed to set object id: %s\n",
            strerror(-response_frame.res));
        RAWSTOR_THROW_ERRNO(EPROTO);
    }

    if (response_frame.cmd != RAWSTOR_CMD_SET_OBJECT) {
        rawstor_error(
            "Unexpected command in response: %d\n",
            response_frame.cmd);
        RAWSTOR_THROW_ERRNO(EPROTO);
    }

    if (rawstor_io_queue_setup_fd(fd)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Socket::_response_head_read() {
    if (rawstor_fd_read(
        _fd,
        &_response_frame, sizeof(_response_frame),
        _response_head_received, this))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


int Socket::_op_process_read(SocketOp *op, int fd) noexcept {
    return rawstor_fd_read(
        fd,
        op->payload.linear.data, op->request_frame.len,
        _response_body_received, op);
}


int Socket::_op_process_readv(SocketOp *op, int fd) noexcept {
    return rawstor_fd_readv(
        fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request_frame.len,
        _responsev_body_received, op);
}


int Socket::_op_process_write(
    SocketOp *op, int) noexcept
{
    Socket *s = op->s;
    int ret = 0;

    try {
        /**
         * Continue response loop, if there are any other pending operations.
         */
        if (
            rawstor_ringbuf_size(s->_ops) <
            rawstor_ringbuf_capacity(s->_ops) - 1)
        {
            s->_response_head_read();
        } else {
            s->_response_loop = 0;
        }

        ret = op->callback(
            s->_object->c_ptr(),
            op->request_frame.len, op->request_frame.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    SocketOp **it = (SocketOp**)rawstor_ringbuf_head(s->_ops);
    assert(rawstor_ringbuf_push(s->_ops) == 0);
    *it = op;

    return ret;
}


int Socket::_read_request_sent(
    RawstorIOEvent *event, void *data) noexcept
{
    SocketOp *op = (SocketOp*)data;
    Socket *s = op->s;

    try {
        op_trace(op->cid, event);

        if (rawstor_io_event_error(event) != 0) {
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event))
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            rawstor_error(
                "Request size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            RAWSTOR_THROW_ERRNO(EIO)
        }

        /**
         * Start read response loop.
         */
        if (s->_response_loop == 0) {
            s->_response_head_read();
            s->_response_loop = 1;
        }

        return 0;
    } catch (const std::system_error &e) {
        SocketOp **it = (SocketOp**)rawstor_ringbuf_head(s->_ops);
        assert(rawstor_ringbuf_push(s->_ops) == 0);
        *it = op;
        return -e.code().value();
    }
}


int Socket::_write_requestv_sent(
    RawstorIOEvent *event, void *data) noexcept
{
    SocketOp *op = (SocketOp*)data;
    Socket *s = op->s;

    try {
        op_trace(op->cid, event);

        if (rawstor_io_event_error(event) != 0) {
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event))
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            rawstor_error(
                "Request size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            RAWSTOR_THROW_ERRNO(EIO);
        }

        /**
         * Start read response loop.
         */
        if (s->_response_loop == 0) {
            s->_response_head_read();
            s->_response_loop = 1;
        }

        return 0;
    } catch (const std::system_error &e) {
        SocketOp **it = (SocketOp**)rawstor_ringbuf_head(s->_ops);
        assert(rawstor_ringbuf_push(s->_ops) == 0);
        *it = op;
        return -e.code().value();
    }
}


int Socket::_response_body_received(
    RawstorIOEvent *event, void *data) noexcept
{
    /**
     * FIXME: Proper error handling.
     */

    SocketOp *op = (SocketOp*)data;
    Socket *s = op->s;
    int ret = 0;

    try {
        op_trace(op->cid, event);

        uint64_t hash = rawstor_hash_scalar(
            op->payload.linear.data, op->request_frame.len);

        if (s->_response_frame.hash != hash) {
            rawstor_error(
                "Response hash mismatch: %llx != %llx\n",
                (unsigned long long)s->_response_frame.hash,
                (unsigned long long)hash);
            RAWSTOR_THROW_ERRNO(EIO);
        }

        if (rawstor_io_event_error(event) != 0) {
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event));
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            rawstor_error(
                "Response body size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            RAWSTOR_THROW_ERRNO(EIO);
        }

        /**
         * Continue response loop, if there are any other pending operations.
         */
        if (
            rawstor_ringbuf_size(s->_ops) <
            rawstor_ringbuf_capacity(s->_ops) - 1)
        {
            s->_response_head_read();
        } else {
            s->_response_loop = 0;
        }

        ret = op->callback(
            s->_object->c_ptr(),
            op->request_frame.len, op->request_frame.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    SocketOp **it = (SocketOp**)rawstor_ringbuf_head(s->_ops);
    assert(rawstor_ringbuf_push(s->_ops) == 0);
    *it = op;

    return ret;
}


int Socket::_responsev_body_received(
    RawstorIOEvent *event, void *data) noexcept
{
    SocketOp *op = (SocketOp*)data;
    Socket *s = op->s;
    int ret = 0;

    try {
        op_trace(op->cid, event);

        uint64_t hash;
        if (rawstor_hash_vector(
            op->payload.vector.iov, op->payload.vector.niov, &hash))
        {
            return -errno;
        }

        if (s->_response_frame.hash != hash) {
            rawstor_error(
                "Response hash mismatch: %llx != %llx\n",
                (unsigned long long)s->_response_frame.hash,
                (unsigned long long)hash);
            RAWSTOR_THROW_ERRNO(EIO);
        }

        if (rawstor_io_event_error(event) != 0) {
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event));
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            rawstor_error(
                "Response body size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            RAWSTOR_THROW_ERRNO(EIO);
        }

        /**
         * Continue response loop, if there are any other pending operations.
         */
        if (
            rawstor_ringbuf_size(s->_ops) <
            rawstor_ringbuf_capacity(s->_ops) - 1)
        {
            s->_response_head_read();
        } else {
            s->_response_loop = 0;
        }

        ret = op->callback(
            s->_object->c_ptr(),
            op->request_frame.len, op->request_frame.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    SocketOp **it = (SocketOp**)rawstor_ringbuf_head(s->_ops);
    assert(rawstor_ringbuf_push(s->_ops) == 0);
    *it = op;

    return ret;
}


int Socket::_response_head_received(
    RawstorIOEvent *event, void *data) noexcept
{
    Socket *s = (Socket*)data;

    try {
        if (rawstor_io_event_error(event) != 0) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            s->_response_loop = 0;
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event));
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            rawstor_error(
                "Response head size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            s->_response_loop = 0;
            RAWSTOR_THROW_ERRNO(EIO);
        }

        RawstorOSTFrameResponse *response = &s->_response_frame;
        if (response->magic != RAWSTOR_MAGIC) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            rawstor_error(
                "FATAL! Frame with wrong magic number: %x != %x\n",
                response->magic, RAWSTOR_MAGIC);
            RAWSTOR_THROW_ERRNO(EIO);
        }
        if (response->cid < 1 || response->cid > s->_ops_array.size()) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            rawstor_error("Unexpected cid in response: %u\n", response->cid);
            RAWSTOR_THROW_ERRNO(EIO);
        }

        SocketOp *op = s->_ops_array[response->cid - 1];

        op_trace(op->cid, event);

        return op->process(op, rawstor_io_event_fd(event));
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


void Socket::create(
    const RawstorSocketAddress &,
    const RawstorObjectSpec &,
    RawstorUUID *id)
{
    /**
     * TODO: Implement me.
     */
    if (rawstor_uuid7_init(id)) {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Socket::remove(rawstor::Object *, const RawstorSocketAddress &) {
    throw std::runtime_error("Socket::remove() not implemented\n");
}


void Socket::spec(
    rawstor::Object *,
    const RawstorSocketAddress &,
    RawstorObjectSpec *sp)
{
    /**
     * TODO: Implement me.
     */

    *sp = {
        .size = 1 << 30,
    };
}


void Socket::open(
    rawstor::Object *object,
    const RawstorSocketAddress &ost)
{
    if (_fd != -1) {
        throw std::runtime_error("Socket already opened");
    }

    try {
        _fd = _connect(ost);
        _set_object_id(_fd, object->id());
    } catch (...) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Socket::close(): %s\n", e.what());
        }
    }

    _object = object;
}


void Socket::close() {
    if (_fd == -1) {
        throw std::runtime_error("Socket not opened");
    }
    if (::close(_fd) == -1) {
        RAWSTOR_THROW_ERRNO(errno);
    }
    _fd = -1;
    _object = nullptr;
}


void Socket::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    SocketOp **it = (SocketOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    SocketOp *op = *it;

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .request_frame = {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_READ,
                .cid = op->cid,
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = 0,
                .sync = 0,
            },
            .payload = {
                .linear = {
                    .data = buf,
                },
            },
            .iov = {},
            .process = _op_process_read,
            .callback = cb,
            .data = data,
        };

        if (rawstor_fd_write(
            _fd,
            &op->request_frame, sizeof(op->request_frame),
            _read_request_sent, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        SocketOp **it = (SocketOp**)rawstor_ringbuf_head(_ops);
        assert(rawstor_ringbuf_push(_ops) == 0);
        *it = op;
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

    SocketOp **it = (SocketOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    SocketOp *op = *it;

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .request_frame = {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_READ,
                .cid = op->cid,
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = 0,
                .sync = 0,
            },
            .payload = {
                .vector = {
                    .iov = iov,
                    .niov = niov,
                },
            },
            .iov = {},
            .process = _op_process_readv,
            .callback = cb,
            .data = data,
        };

        if (rawstor_fd_write(
            _fd,
            &op->request_frame, sizeof(op->request_frame),
            _read_request_sent, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        SocketOp **it = (SocketOp**)rawstor_ringbuf_head(_ops);
        assert(rawstor_ringbuf_push(_ops) == 0);
        *it = op;
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

    SocketOp **it = (SocketOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    SocketOp *op = *it;

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .request_frame = {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_WRITE,
                .cid = op->cid,
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = rawstor_hash_scalar(buf, size),
                .sync = 0,
            },
            .payload = {
                .linear = {
                    .data = buf,
                },
            },
            .iov = {},
            .process = _op_process_write,
            .callback = cb,
            .data = data,
        };

        op->iov[0] = {
            .iov_base = &op->request_frame,
            .iov_len = sizeof(op->request_frame),
        };
        op->iov[1] = {
            .iov_base = buf,
            .iov_len = size,
        };

        if (rawstor_fd_writev(
            _fd,
            op->iov, 2, sizeof(op->request_frame) + size,
            _write_requestv_sent, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        SocketOp **it = (SocketOp**)rawstor_ringbuf_head(_ops);
        assert(rawstor_ringbuf_push(_ops) == 0);
        *it = op;
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
    if (rawstor_hash_vector(iov, niov, &hash)) {
        RAWSTOR_THROW_ERRNO(errno);
    }

    if (niov >= IOVEC_SIZE) {
        throw std::runtime_error("Large iovecs not supported");
    }

    SocketOp **it = (SocketOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    SocketOp *op = *it;

    try {
        *op = {
            .s = this,
            .cid = op->cid,  // preserve cid
            .request_frame = {
                .magic = RAWSTOR_MAGIC,
                .cmd = RAWSTOR_CMD_WRITE,
                .cid = op->cid,
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash,
                .sync = 0,
            },
            .payload = {
                .vector = {
                    .iov = iov,
                    .niov = niov,
                },
            },
            .iov = {},
            .process = _op_process_write,
            .callback = cb,
            .data = data,
        };

        op->iov[0] = {
            .iov_base = &op->request_frame,
            .iov_len = sizeof(op->request_frame),
        };
        for (unsigned int i = 0; i < niov; ++i) {
            op->iov[i + 1] = iov[i];
        }

        if (rawstor_fd_writev(
            _fd,
            op->iov, niov + 1, sizeof(op->request_frame) + size,
            _write_requestv_sent, op))
        {
            RAWSTOR_THROW_ERRNO(errno);
        }
    } catch (...) {
        SocketOp **it = (SocketOp**)rawstor_ringbuf_head(_ops);
        assert(rawstor_ringbuf_push(_ops) == 0);
        *it = op;
        throw;
    }
}


} // rawstor
