#include "connection_ost.h"

#include "opts.h"
#include "ost_protocol.h"

#include <rawstorio/queue.h>

#include <rawstorstd/gcc.h>
#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/socket.h>

#include <rawstor/object.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

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


struct RawstorConnectionOp {
    RawstorConnection *cn;

    uint16_t cid;
    RawstorOSTFrameIO request_frame;

    union {
        struct {
            void *data;
        } linear;
        struct {
            struct iovec *iov;
            unsigned int niov;
        } vector;
    } payload;

    struct iovec iov[IOVEC_SIZE];

    int (*process)(struct RawstorConnectionOp *op, int fd);

    RawstorCallback *callback;

    void *data;
};


struct RawstorConnection {
    RawstorObject *object;

    int *fds;
    size_t nfds;
    size_t ifds;

    unsigned int depth;

    int response_loop;
    struct RawstorConnectionOp **ops_array;
    RawstorRingBuf *ops;
    RawstorOSTFrameResponse response_frame;
};


static int ost_connect(const struct RawstorSocketAddress *ost) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        goto err_socket;
    }

    unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
    if (so_sndtimeo != 0) {
        if (rawstor_socket_set_snd_timeout(fd, so_sndtimeo)) {
            goto err_set;
        }
    }

    unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
    if (so_rcvtimeo != 0) {
        if (rawstor_socket_set_rcv_timeout(fd, so_rcvtimeo)) {
            goto err_set;
        }
    }

    unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
    if (tcp_user_timeo != 0) {
        if (rawstor_socket_set_user_timeout(fd, tcp_user_timeo)) {
            goto err_set;
        }
    }

    struct sockaddr_in servaddr = {};
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(ost->port);

    int res = inet_pton(AF_INET, ost->host, &servaddr.sin_addr);
    if (res == 0) {
        errno = EINVAL;
        goto err_pton;
    }
    if (res < 0) {
        goto err_pton;
    }

    rawstor_info("Connecting to %s:%u\n", ost->host, ost->port);
    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        goto err_connect;
    }

    return fd;

err_connect:
err_pton:
err_set:
    close(fd);
err_socket:
    return -errno;
}


/**
 * TODO: Do it async or solve partial IO issue.
 */
static int ost_set_object_id(int fd, const struct RawstorUUID *object_id) {
    RawstorOSTFrameBasic request_frame = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
    };
    memcpy(
        request_frame.obj_id,
        object_id->bytes,
        sizeof(request_frame.obj_id));

    int res = write(fd, &request_frame, sizeof(request_frame));
    if (res < 0) {
        return -errno;
    }
    assert(res == sizeof(request_frame));

    RawstorOSTFrameResponse response_frame;
    res = read(fd, &response_frame, sizeof(response_frame));
    if (res < 0) {
        return -errno;
    }
    assert(res == sizeof(response_frame));

    if (response_frame.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "Unexpected magic number: %x != %x\n",
            response_frame.magic, RAWSTOR_MAGIC);
        errno = EPROTO;
        return -errno;
    }

    if (response_frame.res < 0) {
        rawstor_error(
            "Server failed to set object id: %s\n",
            strerror(-response_frame.res));
        errno = EPROTO;
        return -errno;
    }

    if (response_frame.cmd != RAWSTOR_CMD_SET_OBJECT) {
        rawstor_error(
            "Unexpected command in response: %d\n",
            response_frame.cmd);
        errno = EPROTO;
        return -errno;
    }

    if (rawstor_io_queue_setup_fd(fd)) {
        return -errno;
    }

    return 0;
}


static int connection_get_next_fd(RawstorConnection* cn) {
    int fd = cn->fds[cn->ifds++];
    if (cn->ifds >= cn->nfds) {
        cn->ifds = 0;
    }
    return fd;
}


static int connection_response_head_read(struct RawstorConnection *cn);


static int response_body_received(RawstorIOEvent *event, void *data) {
    /**
     * FIXME: Proper error handling.
     */

    struct RawstorConnectionOp *op = (struct RawstorConnectionOp*)data;

    op_trace(op->cid, event);

    uint64_t hash = rawstor_hash_scalar(
        op->payload.linear.data, op->request_frame.len);

    if (op->cn->response_frame.hash != hash) {
        rawstor_error(
            "Response hash mismatch: %llx != %llx\n",
            (unsigned long long)op->cn->response_frame.hash,
            (unsigned long long)hash);
        errno = EIO;
        return -errno;
    }

    if (rawstor_io_event_error(event) != 0) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        rawstor_error(
            "Response body size mismatch: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        errno = EIO;
        return -errno;
    }

    /**
     * Continue response loop, if there are any other pending operations.
     */
    if (rawstor_ringbuf_size(op->cn->ops) < op->cn->depth - 1) {
        if (connection_response_head_read(op->cn)) {
            struct RawstorConnectionOp **it = rawstor_ringbuf_head(
                op->cn->ops);
            assert(rawstor_ringbuf_push(op->cn->ops) == 0);
            *it = op;
            return -errno;
        }
    } else {
        op->cn->response_loop = 0;
    }

    int ret = op->callback(
        op->cn->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    struct RawstorConnectionOp **it = rawstor_ringbuf_head(op->cn->ops);
    assert(rawstor_ringbuf_push(op->cn->ops) == 0);
    *it = op;

    return ret;
}


static int responsev_body_received(RawstorIOEvent *event, void *data) {
    struct RawstorConnectionOp *op = (struct RawstorConnectionOp*)data;

    op_trace(op->cid, event);

    uint64_t hash;
    if (rawstor_hash_vector(
        op->payload.vector.iov, op->payload.vector.niov, &hash))
    {
        return -errno;
    }

    if (op->cn->response_frame.hash != hash) {
        rawstor_error(
            "Response hash mismatch: %llx != %llx\n",
            (unsigned long long)op->cn->response_frame.hash,
            (unsigned long long)hash);
        errno = EIO;
        return -errno;
    }

    if (rawstor_io_event_error(event) != 0) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        rawstor_error(
            "Response body size mismatch: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        errno = EIO;
        return -errno;
    }

    /**
     * Continue response loop, if there are any other pending operations.
     */
    if (rawstor_ringbuf_size(op->cn->ops) < op->cn->depth - 1) {
        if (connection_response_head_read(op->cn)) {
            struct RawstorConnectionOp **it = rawstor_ringbuf_head(
                op->cn->ops);
            assert(rawstor_ringbuf_push(op->cn->ops) == 0);
            *it = op;
            return -errno;
        }
    } else {
        op->cn->response_loop = 0;
    }

    int ret = op->callback(
        op->cn->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    struct RawstorConnectionOp **it = rawstor_ringbuf_head(
        op->cn->ops);
    assert(rawstor_ringbuf_push(op->cn->ops) == 0);
    *it = op;

    return ret;
}


static int response_head_received(RawstorIOEvent *event, void *data) {
    RawstorConnection *cn = (RawstorConnection*)data;

    if (rawstor_io_event_error(event) != 0) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        cn->response_loop = 0;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error(
            "Response head size mismatch: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        cn->response_loop = 0;
        errno = EIO;
        return -errno;
    }

    RawstorOSTFrameResponse *response = &cn->response_frame;
    if (response->magic != RAWSTOR_MAGIC) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error("FATAL! Frame with wrong magic number: %x != %x\n",
                      response->magic, RAWSTOR_MAGIC);
        errno = EIO;
        return -errno;
    }
    if (response->cid < 1 || response->cid > cn->depth) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error("Unexpected cid in response: %u\n", response->cid);
        errno = EIO;
        return -errno;
    }

    struct RawstorConnectionOp *op = cn->ops_array[response->cid - 1];

    op_trace(op->cid, event);

    return op->process(op, rawstor_io_event_fd(event));
}


static int connection_response_head_read(struct RawstorConnection *cn) {
    if (rawstor_fd_read(
        connection_get_next_fd(cn),
        &cn->response_frame, sizeof(cn->response_frame),
        response_head_received, cn))
    {
        return -errno;
    }

    return 0;
}


static int connection_op_process_read(
    struct RawstorConnectionOp *op, int fd)
{
    return rawstor_fd_read(
        fd,
        op->payload.linear.data, op->request_frame.len,
        response_body_received, op);
}


static int connection_op_process_readv(
    struct RawstorConnectionOp *op, int fd)
{
    return rawstor_fd_readv(
        fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request_frame.len,
        responsev_body_received, op);
}


static int connection_op_process_write(
    struct RawstorConnectionOp *op, int RAWSTOR_UNUSED fd)
{
    /**
     * Continue response loop, if there are any other pending operations.
     */
    if (rawstor_ringbuf_size(op->cn->ops) < op->cn->depth - 1) {
        if (connection_response_head_read(op->cn)) {
            struct RawstorConnectionOp **it = rawstor_ringbuf_head(
                op->cn->ops);
            assert(rawstor_ringbuf_push(op->cn->ops) == 0);
            *it = op;
            return -errno;
        }
    } else {
        op->cn->response_loop = 0;
    }

    int ret = op->callback(
        op->cn->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    struct RawstorConnectionOp **it = rawstor_ringbuf_head(op->cn->ops);
    assert(rawstor_ringbuf_push(op->cn->ops) == 0);
    *it = op;

    return ret;
}


static int read_request_sent(RawstorIOEvent *event, void *data) {
    struct RawstorConnectionOp *op = (struct RawstorConnectionOp*)data;

    op_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        rawstor_error(
            "Request size mismatch: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        errno = EIO;
        return -errno;
    }

    /**
     * Start read response loop.
     */
    if (op->cn->response_loop == 0) {
        if (connection_response_head_read(op->cn)) {
            return -errno;
        }
        op->cn->response_loop = 1;
    }

    return 0;
}


static int write_requestv_sent(RawstorIOEvent *event, void *data) {
    struct RawstorConnectionOp *op = (struct RawstorConnectionOp*)data;

    op_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        struct RawstorConnectionOp **it = rawstor_ringbuf_head(
            op->cn->ops);
        assert(rawstor_ringbuf_push(op->cn->ops) == 0);
        *it = op;
        rawstor_error(
            "Request size mismatch: %zu != %zu\n",
            rawstor_io_event_result(event),
            rawstor_io_event_size(event));
        errno = EIO;
        return -errno;
    }

    /**
     * Start read response loop.
     */
    if (op->cn->response_loop == 0) {
        if (connection_response_head_read(op->cn)) {
            return -errno;
        }
        op->cn->response_loop = 1;
    }

    return 0;
}


RawstorConnection* rawstor_connection_open(
    RawstorObject *object,
    const struct RawstorSocketAddress *ost,
    size_t count,
    unsigned int depth)
{
    RawstorConnection *cn = malloc(sizeof(RawstorConnection));
    if (cn == NULL) {
        goto err_cn;
    }
    *cn = (RawstorConnection) {
        .object = object,
        .nfds = count,
        .ifds = 0,
        .depth = depth,
        .response_loop = 0,
    };

    cn->fds = calloc(count, sizeof(int));
    if (cn->fds == NULL) {
        goto err_fds;
    }
    for (size_t i = 0; i < cn->nfds; ++i) {
        cn->fds[i] = -1;
    }

    for (size_t i = 0; i < cn->nfds; ++i) {
        cn->fds[i] = ost_connect(ost);
        if (cn->fds[i] < 0) {
            goto err_connect;
        }

        if (ost_set_object_id(cn->fds[i], rawstor_object_get_id(object))) {
            goto err_set_object_id;
        }
    }

    cn->ops_array = calloc(
        cn->depth, sizeof(struct RawstorConnectionOp*));
    if (cn->ops_array == NULL) {
        goto err_ops_array;
    }

    cn->ops = rawstor_ringbuf_create(
        cn->depth, sizeof(struct RawstorConnectionOp*));
    if (cn->ops == NULL) {
        goto err_ops;
    }

    for (unsigned int i = 0; i < cn->depth; ++i) {
        struct RawstorConnectionOp *op = malloc(
            sizeof(struct RawstorConnectionOp));
        if (op == NULL) {
            goto err_op;
        }

        op->cid = i + 1;

        cn->ops_array[i] = op;

        struct RawstorConnectionOp **it = rawstor_ringbuf_head(cn->ops);
        assert(rawstor_ringbuf_push(cn->ops) == 0);
        *it = op;
    }

    return cn;

    int errsv;
err_op:
    for (unsigned int i = 0; i < cn->depth; ++i) {
        free(cn->ops_array[i]);
    }
    rawstor_ringbuf_delete(cn->ops);
err_ops:
    free(cn->ops_array);
err_ops_array:
err_set_object_id:
err_connect:
    errsv = errno;
    for (size_t i = 0; i < cn->nfds; ++i) {
        if (cn->fds[i] >= 0) {
            close(cn->fds[i]);
            cn->fds[i] = -1;
        }
    }
    errno = errsv;
    free(cn->fds);
err_fds:
    free(cn);
err_cn:
    return NULL;
}


int rawstor_connection_close(RawstorConnection *cn) {
    for (size_t i = 0; i < cn->nfds; ++i) {
        if (cn->fds[i] >= 0) {
            int rval = close(cn->fds[i]);
            if (rval == -1) {
                return -errno;
            }
            cn->fds[i] = -1;
        }
    }

    for (unsigned int i = 0; i < cn->depth; ++i) {
        free(cn->ops_array[i]);
    }
    rawstor_ringbuf_delete(cn->ops);
    free(cn->ops_array);

    free(cn->fds);
    free(cn);

    return 0;
}


int rawstor_connection_pread(
    RawstorConnection *cn,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    struct RawstorConnectionOp **it = rawstor_ringbuf_tail(cn->ops);
    if (rawstor_ringbuf_pop(cn->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    struct RawstorConnectionOp *op = *it;

    *op = (struct RawstorConnectionOp) {
        .cn = cn,
        .cid = op->cid,  // preserve cid
        .request_frame = (RawstorOSTFrameIO) {
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_READ,
            .cid = op->cid,
            .offset = offset,
            .len = size,
            .sync = 0,
        },
        // .response_frame =
        .payload.linear.data = buf,
        // .iov
        .process = connection_op_process_read,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_write(
        connection_get_next_fd(cn),
        &op->request_frame, sizeof(op->request_frame),
        read_request_sent, op);
}


int rawstor_connection_preadv(
    RawstorConnection *cn,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    struct RawstorConnectionOp **it = rawstor_ringbuf_tail(cn->ops);
    if (rawstor_ringbuf_pop(cn->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    struct RawstorConnectionOp *op = *it;

    *op = (struct RawstorConnectionOp) {
        .cn = cn,
        .cid = op->cid,  // preserve cid
        .request_frame = (RawstorOSTFrameIO) {
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_READ,
            .cid = op->cid,
            .offset = offset,
            .len = size,
        },
        // .response_frame
        .payload.vector.iov = iov,
        .payload.vector.niov = niov,
        // .iov
        .process = connection_op_process_readv,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_write(
        connection_get_next_fd(cn),
        &op->request_frame, sizeof(op->request_frame),
        read_request_sent, op);
}


int rawstor_connection_pwrite(
    RawstorConnection *cn,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    struct RawstorConnectionOp **it = rawstor_ringbuf_tail(cn->ops);
    if (rawstor_ringbuf_pop(cn->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    struct RawstorConnectionOp *op = *it;

    *op = (struct RawstorConnectionOp) {
        .cn = cn,
        .cid = op->cid,  // preserve cid
        .request_frame = (RawstorOSTFrameIO) {
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = op->cid,
            .offset = offset,
            .len = size,
            .hash = rawstor_hash_scalar(buf, size),
            .sync = 0,
        },
        // .response_frame =
        .payload.linear.data = buf,
        // .iov
        .process = connection_op_process_write,
        .callback = cb,
        .data = data,
    };

    op->iov[0] = (struct iovec) {
        .iov_base = &op->request_frame,
        .iov_len = sizeof(op->request_frame),
    };
    op->iov[1] = (struct iovec) {
        .iov_base = buf,
        .iov_len = size,
    };
    return rawstor_fd_writev(
        connection_get_next_fd(cn),
        op->iov, 2, sizeof(op->request_frame) + size,
        write_requestv_sent, op);
}


int rawstor_connection_pwritev(
    RawstorConnection *cn,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    uint64_t hash;
    if (rawstor_hash_vector(iov, niov, &hash)) {
        return -errno;
    }

    if (niov >= IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    struct RawstorConnectionOp **it = rawstor_ringbuf_tail(cn->ops);
    if (rawstor_ringbuf_pop(cn->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    struct RawstorConnectionOp *op = *it;

    *op = (struct RawstorConnectionOp) {
        .cn = cn,
        .cid = op->cid,  // preserve cid
        .request_frame = (RawstorOSTFrameIO) {
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = op->cid,
            .offset = offset,
            .len = size,
            .hash = hash,
            .sync = 0,
        },
        // .response_frame =
        .payload.vector.iov = iov,
        .payload.vector.niov = niov,
        // .iov
        .process = connection_op_process_write,
        .callback = cb,
        .data = data,
    };

    op->iov[0] = (struct iovec) {
        .iov_base = &op->request_frame,
        .iov_len = sizeof(op->request_frame),
    };
    for (unsigned int i = 0; i < niov; ++i) {
        op->iov[i + 1] = iov[i];
    }
    return rawstor_fd_writev(
        connection_get_next_fd(cn),
        op->iov, niov + 1, sizeof(op->request_frame) + size,
        write_requestv_sent, op);
}
