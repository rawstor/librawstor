#include <rawstor/object.h>
#include "object_internals.h"

#include "opts.h"
#include "ost_protocol.h"

#include <rawstorstd/hash.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/socket.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/io.h>

#include <arpa/inet.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256


#define operation_trace(cid, event) \
    rawstor_debug( \
        "[%u] %s(): %zi of %zu\n", \
        cid, __FUNCTION__, \
        rawstor_io_event_result(event), \
        rawstor_io_event_size(event))


typedef struct RawstorObjectOperation RawstorObjectOperation;


struct RawstorObjectOperation {
    RawstorObject *object;

    u_int16_t cid;
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

    int (*process)(RawstorObjectOperation *op);

    RawstorCallback *callback;

    void *data;
};


struct RawstorObject {
    int fd;
    int response_loop;
    RawstorMemPool *operations_pool;
    RawstorOSTFrameResponse response_frame;
};


static int response_body_received(RawstorIOEvent *event, void *data);


static int responsev_body_received(RawstorIOEvent *event, void *data);


static int operation_process_read(RawstorObjectOperation *op) {
    return rawstor_fd_read(
        op->object->fd,
        op->payload.linear.data, op->request_frame.len,
        response_body_received, op);
}


static int operation_process_readv(RawstorObjectOperation *op) {
    return rawstor_fd_readv(
        op->object->fd,
        op->payload.vector.iov, op->payload.vector.niov, op->request_frame.len,
        responsev_body_received, op);
}


static int object_response_head_recv(RawstorObject *object);


static int operation_process_write(RawstorObjectOperation *op) {
    /**
     * Continue response loop, if there are any other pending operations.
     */
    if (rawstor_mempool_allocated(op->object->operations_pool) > 1) {
        if (object_response_head_recv(op->object)) {
            rawstor_mempool_free(op->object->operations_pool, op);
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    rawstor_mempool_free(op->object->operations_pool, op);

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


static int ost_connect(const RawstorOptsOST *opts_ost) {
    struct sockaddr_in servaddr;
    // socket create and verification
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return -errno;
    }

    rawstor_info("Socket successfully created\n");

    unsigned int so_sndtimeo = rawstor_opts_ost_so_sndtimeo(opts_ost);
    if (so_sndtimeo != 0) {
        if (rawstor_socket_set_snd_timeout(fd, so_sndtimeo)) {
            return -errno;
        }
    }

    unsigned int so_rcvtimeo = rawstor_opts_ost_so_rcvtimeo(opts_ost);
    if (so_rcvtimeo != 0) {
        if (rawstor_socket_set_rcv_timeout(fd, so_sndtimeo)) {
            return -errno;
        }
    }

    unsigned int tcp_user_timeo = rawstor_opts_ost_tcp_user_timeout(opts_ost);
    if (tcp_user_timeo != 0) {
        if (rawstor_socket_set_user_timeout(fd, tcp_user_timeo)) {
            return -errno;
        }
    }

    const char *host = rawstor_opts_ost_host(opts_ost);
    unsigned int port = rawstor_opts_ost_port(opts_ost);

    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(host);
    servaddr.sin_port = htons(port);

    rawstor_info("Connecting to %s:%u\n", host, port);
    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        return -errno;
    }

    return fd;
}


static int read_request_sent(RawstorIOEvent *event, void *data) {
    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    operation_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        rawstor_mempool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_mempool_free(op->object->operations_pool, op);
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
    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    operation_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        rawstor_mempool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_mempool_free(op->object->operations_pool, op);
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

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

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
        rawstor_mempool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_mempool_free(op->object->operations_pool, op);
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
    if (rawstor_mempool_allocated(op->object->operations_pool) > 1) {
        if (object_response_head_recv(op->object)) {
            rawstor_mempool_free(op->object->operations_pool, op);
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    rawstor_mempool_free(op->object->operations_pool, op);

    return ret;
}


static int responsev_body_received(RawstorIOEvent *event, void *data) {
    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

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
        rawstor_mempool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_mempool_free(op->object->operations_pool, op);
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
    if (rawstor_mempool_allocated(op->object->operations_pool) > 1) {
        if (object_response_head_recv(op->object)) {
            rawstor_mempool_free(op->object->operations_pool, op);
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    rawstor_mempool_free(op->object->operations_pool, op);

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
    if (
        response->cid < 1 ||
        response->cid > rawstor_mempool_capacity(object->operations_pool)
    ) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error("Unexpected cid in response: %u\n", response->cid);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *ops = rawstor_mempool_data(object->operations_pool);
    RawstorObjectOperation *op = &ops[response->cid - 1];

    operation_trace(op->cid, event);

    return op->process(op);
}


const char *rawstor_object_backend_name(void) {
    return "ost";
};


int rawstor_object_create(
    const RawstorOptsOST RAWSTOR_UNUSED *opts_ost,
    const RawstorObjectSpec RAWSTOR_UNUSED *spec,
    RawstorUUID *object_id)
{
    /**
     * TODO: Implement me.
     */
    rawstor_uuid7_init(object_id);

    return 0;
}


int rawstor_object_delete(
    const RawstorOptsOST RAWSTOR_UNUSED *opts_ost,
    const RawstorUUID RAWSTOR_UNUSED *object_id)
{
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

    return 0;
}


int rawstor_object_open(
    const RawstorOptsOST *opts_ost,
    const RawstorUUID *object_id,
    RawstorObject **object)
{
    int errsv;
    RawstorObject *obj = malloc(sizeof(RawstorObject));
    if (obj == NULL) {
        goto err_obj;
    }
    obj->response_loop = 0;

    obj->operations_pool = rawstor_mempool_create(
        QUEUE_DEPTH,
        sizeof(RawstorObjectOperation));
    if (obj->operations_pool == NULL) {
        goto err_operations_pool;
    }
    RawstorObjectOperation *ops = rawstor_mempool_data(obj->operations_pool);
    for (unsigned int i = 0; i < QUEUE_DEPTH; ++i) {
        ops[i].cid = i + 1;
    }

    obj->fd = ost_connect(opts_ost);
    if (obj->fd < 0) {
        goto err_connect;
    }

    RawstorOSTFrameBasic mframe = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
    };
    memcpy(mframe.obj_id, object_id->bytes, sizeof(mframe.obj_id));
    int res = write(obj->fd, &mframe, sizeof(mframe));
    rawstor_debug("Sent request to set objid, res:%i\n", res);
    if (res < 0) {
        goto err_write;
    }
    RawstorOSTFrameResponse rframe;
    res = read(obj->fd, &rframe, sizeof(rframe));
    if (res < 0) {
        goto err_read;
    }
    if (rframe.magic != RAWSTOR_MAGIC) {
        rawstor_error(
            "FATAL! Frame with wrong magic number: %x != %x\n",
            rframe.magic, RAWSTOR_MAGIC);
        errno = EIO;
        goto err_rawstor_magic;
    }
    rawstor_debug(
        "Response from Server: cmd:%i res:%i\n",
        rframe.cmd,
        rframe.res);

    if (rawstor_io_setup_fd(obj->fd)) {
        goto err_setup_fd;
    }

    *object = obj;

    return 0;

err_setup_fd:
err_rawstor_magic:
err_read:
err_write:
    errsv = errno;
    close(obj->fd);
    errno = errsv;
err_connect:
    errsv = errno;
    rawstor_mempool_delete(obj->operations_pool);
    errno = errsv;
err_operations_pool:
    free(obj);
err_obj:
    return -errno;
}


int rawstor_object_close(RawstorObject *object) {
    int rval = close(object->fd);
    if (rval == -1) {
        return -errno;
    }

    free(object);

    return 0;
}


int rawstor_object_spec(
    const RawstorOptsOST RAWSTOR_UNUSED *opts_ost,
    const RawstorUUID RAWSTOR_UNUSED *object_id,
     RawstorObjectSpec *spec)
{
    /**
     * TODO: Implement me.
     */

    *spec = (RawstorObjectSpec) {
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

    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
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

    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    if (niov >= IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
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

    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
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

    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    if (niov > IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
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
