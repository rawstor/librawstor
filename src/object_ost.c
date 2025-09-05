#include <rawstor/object.h>
#include "object_internals.h"

#include "connection_ost.h"
#include "opts.h"
#include "ost_protocol.h"
#include "rawstor_internals.h"

#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <arpa/inet.h>

#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


struct RawstorObjectOp {
    RawstorObject *object;

    RawstorCallback *callback;

    void *data;
};


struct RawstorObject {
    struct RawstorUUID id;

    RawstorConnection *cn;

    struct RawstorObjectOp *ops_pool;
};


static int response_body_received(RawstorIOEvent *event, void *data);


static int responsev_body_received(RawstorIOEvent *event, void *data);


static int operation_process_read(RawstorObjectOp *op) {
    return rawstor_fd_read(
        op->object->fd,
        op->payload.linear.data, op->request_frame.len,
        response_body_received, op);
}


static int operation_process_readv(RawstorObjectOp *op) {
    return rawstor_fd_readv(
        op->object->fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request_frame.len,
        responsev_body_received, op);
}


static int object_response_head_recv(RawstorObject *object);


static int operation_process_write(RawstorObjectOp *op) {
    /**
     * Continue response loop, if there are any other pending operations.
     */
    if (rawstor_ringbuf_size(op->object->ops) < QUEUE_DEPTH - 1) {
        if (object_response_head_recv(op->object)) {
            RawstorObjectOp **it = rawstor_ringbuf_head(
                op->object->ops);
            assert(rawstor_ringbuf_push(op->object->ops) == 0);
            *it = op;
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    RawstorObjectOp **it = rawstor_ringbuf_head(op->object->ops);
    assert(rawstor_ringbuf_push(op->object->ops) == 0);
    *it = op;

    return ret;
}


static int response_head_received(RawstorIOEvent *event, void *data);


static int object_response_head_recv(RawstorObject *object) {
    if (rawstor_fd_read(
        object->fd,
        &object->response_frame, sizeof(object->response_frame),
        response_head_received, object))
    {
        return -errno;
    }

    return 0;
}


static int read_request_sent(RawstorIOEvent *event, void *data) {
    RawstorObjectOp *op = (RawstorObjectOp*)data;

    operation_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
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
    if (op->object->response_loop == 0) {
        if (object_response_head_recv(op->object)) {
            return -errno;
        }
        op->object->response_loop = 1;
    }

    return 0;
}


static int write_requestv_sent(RawstorIOEvent *event, void *data) {
    RawstorObjectOp *op = (RawstorObjectOp*)data;

    operation_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
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
    if (op->object->response_loop == 0) {
        if (object_response_head_recv(op->object)) {
            return -errno;
        }
        op->object->response_loop = 1;
    }

    return 0;
}


static int response_body_received(RawstorIOEvent *event, void *data) {
    /**
     * FIXME: Proper error handling.
     */

    RawstorObjectOp *op = (RawstorObjectOp*)data;

    operation_trace(op->cid, event);

    uint64_t hash = rawstor_hash_scalar(
        op->payload.linear.data, op->request_frame.len);

    if (op->object->response_frame.hash != hash) {
        rawstor_error(
            "Response hash mismatch: %llx != %llx\n",
            (unsigned long long)op->object->response_frame.hash,
            (unsigned long long)hash);
        errno = EIO;
        return -errno;
    }

    if (rawstor_io_event_error(event) != 0) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
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
    if (rawstor_ringbuf_size(op->object->ops) < QUEUE_DEPTH - 1) {
        if (object_response_head_recv(op->object)) {
            RawstorObjectOp **it = rawstor_ringbuf_head(
                op->object->ops);
            assert(rawstor_ringbuf_push(op->object->ops) == 0);
            *it = op;
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    RawstorObjectOp **it = rawstor_ringbuf_head(op->object->ops);
    assert(rawstor_ringbuf_push(op->object->ops) == 0);
    *it = op;

    return ret;
}


static int responsev_body_received(RawstorIOEvent *event, void *data) {
    RawstorObjectOp *op = (RawstorObjectOp*)data;

    operation_trace(op->cid, event);

    uint64_t hash;
    if (rawstor_hash_vector(
        op->payload.vector.iov, op->payload.vector.niov, &hash))
    {
        return -errno;
    }

    if (op->object->response_frame.hash != hash) {
        rawstor_error(
            "Response hash mismatch: %llx != %llx\n",
            (unsigned long long)op->object->response_frame.hash,
            (unsigned long long)hash);
        errno = EIO;
        return -errno;
    }

    if (rawstor_io_event_error(event) != 0) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
        *it = op;
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        RawstorObjectOp **it = rawstor_ringbuf_head(
            op->object->ops);
        assert(rawstor_ringbuf_push(op->object->ops) == 0);
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
    if (rawstor_ringbuf_size(op->object->ops) < QUEUE_DEPTH - 1) {
        if (object_response_head_recv(op->object)) {
            RawstorObjectOp **it = rawstor_ringbuf_head(
                op->object->ops);
            assert(rawstor_ringbuf_push(op->object->ops) == 0);
            *it = op;
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    RawstorObjectOp **it = rawstor_ringbuf_head(
        op->object->ops);
    assert(rawstor_ringbuf_push(op->object->ops) == 0);
    *it = op;

    return ret;
}


static int response_head_received(RawstorIOEvent *event, void *data) {
    RawstorObject *object = (RawstorObject*)data;

    if (rawstor_io_event_error(event) != 0) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        object->response_loop = 0;
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
        object->response_loop = 0;
        errno = EIO;
        return -errno;
    }

    RawstorOSTFrameResponse *response = &object->response_frame;
    if (response->magic != RAWSTOR_MAGIC) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error("FATAL! Frame with wrong magic number: %x != %x\n",
                      response->magic, RAWSTOR_MAGIC);
        errno = EIO;
        return -errno;
    }
    if (response->cid < 1 || response->cid > QUEUE_DEPTH) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error("Unexpected cid in response: %u\n", response->cid);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOp *op = object->ops_array[response->cid - 1];

    operation_trace(op->cid, event);

    return op->process(op);
}


const char* rawstor_object_backend_name(void) {
    return "ost";
};


int rawstor_object_create(
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id)
{
    return rawstor_object_create_ost(rawstor_default_ost(), spec, object_id);
}


int rawstor_object_create_ost(
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const struct RawstorObjectSpec RAWSTOR_UNUSED *spec,
    struct RawstorUUID *object_id)
{
    /**
     * TODO: Implement me.
     */
    rawstor_uuid7_init(object_id);

    return 0;
}


int rawstor_object_delete(const struct RawstorUUID *object_id) {
    return rawstor_object_delete_ost(rawstor_default_ost(), object_id);
}


int rawstor_object_delete_ost(
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const struct RawstorUUID RAWSTOR_UNUSED *object_id)
{
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

    return 0;
}


int rawstor_object_open(
    const struct RawstorUUID *object_id,
    RawstorObject **object)
{
    return rawstor_object_open_ost(rawstor_default_ost(), object_id, object);
}


int rawstor_object_open_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    RawstorObject **object)
{
    RawstorObject *obj = malloc(sizeof(RawstorObject));
    if (obj == NULL) {
        goto err_obj;
    }

    obj->id = *object_id;

    obj->ops_pool = rawstor_mempool_create(
        QUEUE_DEPTH, sizeof(struct RawstorObjectOp));
    if (obj->ops_pool == NULL) {
        goto err_ops_pool;
    }

    obj->cn = rawstor_connection_create(obj, ost, &obj->id, 1, QUEUE_DEPTH);
    if (obj->cn == NULL) {
        goto err_cn;
    }

    *object = obj;

    return 0;

err_cn:
    rawstor_mempool_delete(obj->ops_pool);
err_ops_pool:
    free(obj);
err_obj:
    return -errno;
}


int rawstor_object_close(RawstorObject *object) {
    for (unsigned int i = 0; i < QUEUE_DEPTH; ++i) {
        free(object->ops_array[i]);
    }

    free(object->ops_array);

    rawstor_mempool_delete(object->ops_pool);

    free(object);

    return 0;
}


const struct RawstorUUID* rawstor_object_get_id(RawstorObject *object) {
    return &object->id;
}


int rawstor_object_spec(
    const struct RawstorUUID *object_id,
    struct RawstorObjectSpec *spec)
{
    return rawstor_object_spec_ost(rawstor_default_ost(), object_id, spec);
}


int rawstor_object_spec_ost(
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const struct RawstorUUID RAWSTOR_UNUSED *object_id,
    struct RawstorObjectSpec *spec)
{
    /**
     * TODO: Implement me.
     */

    *spec = (struct RawstorObjectSpec) {
        .size = 1 << 30,
    };

    return 0;
}


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    RawstorObjectOp **it = rawstor_ringbuf_tail(object->ops);
    if (rawstor_ringbuf_pop(object->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOp *op = *it;

    *op = (RawstorObjectOp) {
        .object = object,
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
        .process = operation_process_read,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_write(
        object->fd, &op->request_frame, sizeof(op->request_frame),
        read_request_sent, op);
}


int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    if (niov >= IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOp **it = rawstor_ringbuf_tail(object->ops);
    if (rawstor_ringbuf_pop(object->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOp *op = *it;

    *op = (RawstorObjectOp) {
        .object = object,
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
        .process = operation_process_readv,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_write(
        object->fd, &op->request_frame, sizeof(op->request_frame),
        read_request_sent, op);
}


int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    RawstorObjectOp **it = rawstor_ringbuf_tail(object->ops);
    if (rawstor_ringbuf_pop(object->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOp *op = *it;

    *op = (RawstorObjectOp) {
        .object = object,
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
        .process = operation_process_write,
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
        object->fd,
        op->iov, 2, sizeof(op->request_frame) + size,
        write_requestv_sent, op);
}


int rawstor_object_pwritev(
    RawstorObject *object,
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

    if (niov > IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOp **it = rawstor_ringbuf_tail(object->ops);
    if (rawstor_ringbuf_pop(object->ops)) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOp *op = *it;

    *op = (RawstorObjectOp) {
        .object = object,
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
        .process = operation_process_write,
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
        object->fd,
        op->iov, niov + 1, sizeof(op->request_frame) + size,
        write_requestv_sent, op);
}
