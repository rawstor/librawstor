#include "connection_ost.hpp"

#include "object_ost.hpp"
#include "opts.h"
#include "ost_protocol.h"

#include <rawstorio/queue.h>

#include <rawstorstd/gcc.h>
#include <rawstorstd/gpp.hpp>
#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/socket.h>

#include <rawstor/object.h>

#include <arpa/inet.h>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>
#include <stdexcept>

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


struct ConnectionOp {
    rawstor::Connection *cn;

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

    int (*process)(ConnectionOp *op, int fd);

    RawstorCallback *callback;

    void *data;
};


Connection::Connection(rawstor::Object &object, unsigned int depth):
    _object(object),
    _ifds(0),
    _depth(depth),
    _response_loop(0),
    _ops_array(),
    _ops(NULL)
{
    try {
        _ops = rawstor_ringbuf_create(
            _depth, sizeof(ConnectionOp*));
        if (_ops == NULL) {
            RAWSTOR_THROW_ERRNO(errno);
        }

        _ops_array.reserve(_depth);
        for (unsigned int i = 0; i < _depth; ++i) {
            ConnectionOp *op = new ConnectionOp();
            op->cid = i + 1;

            _ops_array.push_back(op);

            ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(_ops);
            assert(rawstor_ringbuf_push(_ops) == 0);
            *it = op;
        }
    } catch (...) {
        for (
            std::vector<ConnectionOp*>::iterator it = _ops_array.begin();
            it != _ops_array.end();
            ++it)
        {
            delete *it;
        }
        rawstor_ringbuf_delete(_ops);
        throw;
    }
}


Connection::~Connection() {
    if (!_fds.empty()) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Connection::close(): %s\n", e.what());
        }
    }

    for (
        std::vector<ConnectionOp*>::iterator it = _ops_array.begin();
        it != _ops_array.end();
        ++it)
    {
        delete *it;
    }

    rawstor_ringbuf_delete(_ops);
}


int Connection::_get_next_fd() {
    if (_fds.empty()) {
        throw std::runtime_error("Connection not opened");
    }

    int fd = _fds[_ifds++];
    if (_ifds >= _fds.size()) {
        _ifds = 0;
    }
    return fd;
}


int Connection::_connect(const RawstorSocketAddress &ost) {
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
void Connection::_set_object_id(int fd) {
    RawstorOSTFrameBasic request_frame = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
        .obj_id = {},
        .offset = 0,
        .val = 0,
    };
    memcpy(
        request_frame.obj_id,
        _object.id().bytes,
        sizeof(request_frame.obj_id));

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


void Connection::_response_head_read() {
    if (rawstor_fd_read(
        _get_next_fd(),
        &_response_frame, sizeof(_response_frame),
        _response_head_received, this))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


int Connection::_op_process_read(ConnectionOp *op, int fd) noexcept {
    return rawstor_fd_read(
        fd,
        op->payload.linear.data, op->request_frame.len,
        _response_body_received, op);
}


int Connection::_op_process_readv(ConnectionOp *op, int fd) noexcept {
    return rawstor_fd_readv(
        fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request_frame.len,
        _responsev_body_received, op);
}


int Connection::_op_process_write(
    ConnectionOp *op, int RAWSTOR_UNUSED fd) noexcept
{
    Connection *cn = op->cn;
    int ret = 0;

    try {
        /**
         * Continue response loop, if there are any other pending operations.
         */
        if (rawstor_ringbuf_size(cn->_ops) < cn->_depth - 1) {
            cn->_response_head_read();
        } else {
            cn->_response_loop = 0;
        }

        ret = op->callback(
            (RawstorObject*)&cn->_object,
            op->request_frame.len, op->request_frame.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
    assert(rawstor_ringbuf_push(cn->_ops) == 0);
    *it = op;

    return ret;
}


int Connection::_read_request_sent(
    RawstorIOEvent *event, void *data) noexcept
{
    try {
        ConnectionOp *op = (ConnectionOp*)data;
        Connection *cn = op->cn;

        op_trace(op->cid, event);

        if (rawstor_io_event_error(event) != 0) {
            ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
            assert(rawstor_ringbuf_push(cn->_ops) == 0);
            *it = op;
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event))
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
            assert(rawstor_ringbuf_push(cn->_ops) == 0);
            *it = op;
            rawstor_error(
                "Request size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            RAWSTOR_THROW_ERRNO(EIO)
        }

        /**
         * Start read response loop.
         */
        if (cn->_response_loop == 0) {
            cn->_response_head_read();
            cn->_response_loop = 1;
        }

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int Connection::_write_requestv_sent(
    RawstorIOEvent *event, void *data) noexcept
{
    try {
        ConnectionOp *op = (ConnectionOp*)data;
        Connection *cn = op->cn;

        op_trace(op->cid, event);

        if (rawstor_io_event_error(event) != 0) {
            ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
            assert(rawstor_ringbuf_push(cn->_ops) == 0);
            *it = op;
            RAWSTOR_THROW_ERRNO(rawstor_io_event_error(event))
        }

        if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
            ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
            assert(rawstor_ringbuf_push(cn->_ops) == 0);
            *it = op;
            rawstor_error(
                "Request size mismatch: %zu != %zu\n",
                rawstor_io_event_result(event),
                rawstor_io_event_size(event));
            RAWSTOR_THROW_ERRNO(EIO);
        }

        /**
         * Start read response loop.
         */
        if (cn->_response_loop == 0) {
            cn->_response_head_read();
            cn->_response_loop = 1;
        }

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


int Connection::_response_body_received(
    RawstorIOEvent *event, void *data) noexcept
{
    /**
     * FIXME: Proper error handling.
     */

    ConnectionOp *op = (ConnectionOp*)data;
    Connection *cn = op->cn;
    int ret = 0;

    try {
        op_trace(op->cid, event);

        uint64_t hash = rawstor_hash_scalar(
            op->payload.linear.data, op->request_frame.len);

        if (cn->_response_frame.hash != hash) {
            rawstor_error(
                "Response hash mismatch: %llx != %llx\n",
                (unsigned long long)cn->_response_frame.hash,
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
        if (rawstor_ringbuf_size(cn->_ops) < cn->_depth - 1) {
            cn->_response_head_read();
        } else {
            cn->_response_loop = 0;
        }

        ret = op->callback(
            (RawstorObject*)&cn->_object,
            op->request_frame.len, op->request_frame.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
    assert(rawstor_ringbuf_push(cn->_ops) == 0);
    *it = op;

    return ret;
}


int Connection::_responsev_body_received(
    RawstorIOEvent *event, void *data) noexcept
{
    ConnectionOp *op = (ConnectionOp*)data;
    Connection *cn = op->cn;
    int ret = 0;

    try {
        op_trace(op->cid, event);

        uint64_t hash;
        if (rawstor_hash_vector(
            op->payload.vector.iov, op->payload.vector.niov, &hash))
        {
            return -errno;
        }

        if (cn->_response_frame.hash != hash) {
            rawstor_error(
                "Response hash mismatch: %llx != %llx\n",
                (unsigned long long)cn->_response_frame.hash,
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
        if (rawstor_ringbuf_size(cn->_ops) < cn->_depth - 1) {
            cn->_response_head_read();
        } else {
            cn->_response_loop = 0;
        }

        ret = op->callback(
            (RawstorObject*)&cn->_object,
            op->request_frame.len, op->request_frame.len, 0,
            op->data);
    } catch (const std::system_error &e) {
        ret = -e.code().value();
    }

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_head(cn->_ops);
    assert(rawstor_ringbuf_push(cn->_ops) == 0);
    *it = op;

    return ret;
}


int Connection::_response_head_received(
    RawstorIOEvent *event, void *data) noexcept
{
    Connection *cn = (Connection*)data;

    try {
        if (rawstor_io_event_error(event) != 0) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            cn->_response_loop = 0;
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
            cn->_response_loop = 0;
            RAWSTOR_THROW_ERRNO(EIO);
        }

        RawstorOSTFrameResponse *response = &cn->_response_frame;
        if (response->magic != RAWSTOR_MAGIC) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            rawstor_error(
                "FATAL! Frame with wrong magic number: %x != %x\n",
                response->magic, RAWSTOR_MAGIC);
            RAWSTOR_THROW_ERRNO(EIO);
        }
        if (response->cid < 1 || response->cid > cn->_depth) {
            /**
             * FIXME: Memory leak on used RawstorObjectOperation.
             */
            rawstor_error("Unexpected cid in response: %u\n", response->cid);
            RAWSTOR_THROW_ERRNO(EIO);
        }

        ConnectionOp *op = cn->_ops_array[response->cid - 1];

        op_trace(op->cid, event);

        return op->process(op, rawstor_io_event_fd(event));
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
}


void Connection::open(const RawstorSocketAddress &ost, size_t count) {
    if (!_fds.empty()) {
        throw std::runtime_error("Connection already opened");
    }

    try {
        _fds.reserve(count);
        for (size_t i = 0; i < count; ++i) {
            int fd = _connect(ost);

            _set_object_id(fd);

            _fds.push_back(fd);
        }
    } catch (...) {
        try {
            close();
        } catch (const std::system_error &e) {
            rawstor_error("Connection::close(): %s\n", e.what());
        }
    }
}


void Connection::close() {
    while (!_fds.empty()) {
        if (::close(_fds.back()) == -1) {
            RAWSTOR_THROW_ERRNO(errno);
        }
        _fds.pop_back();
    }
}


void Connection::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    ConnectionOp *op = *it;

    *op = {
        .cn = this,
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
        _get_next_fd(),
        &op->request_frame, sizeof(op->request_frame),
        _read_request_sent, op))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    ConnectionOp *op = *it;

    *op = {
        .cn = this,
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
        _get_next_fd(),
        &op->request_frame, sizeof(op->request_frame),
        _read_request_sent, op))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    ConnectionOp *op = *it;

    *op = {
        .cn = this,
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
        _get_next_fd(),
        op->iov, 2, sizeof(op->request_frame) + size,
        _write_requestv_sent, op))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


void Connection::pwritev(
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

    ConnectionOp **it = (ConnectionOp**)rawstor_ringbuf_tail(_ops);
    if (rawstor_ringbuf_pop(_ops)) {
        RAWSTOR_THROW_ERRNO(ENOBUFS);
    }
    ConnectionOp *op = *it;

    *op = {
        .cn = this,
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
        _get_next_fd(),
        op->iov, niov + 1, sizeof(op->request_frame) + size,
        _write_requestv_sent, op))
    {
        RAWSTOR_THROW_ERRNO(errno);
    }
}


} // rawstor
