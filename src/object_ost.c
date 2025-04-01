#include <rawstor.h>

#include "gcc.h"
#include "io.h"
#include "logging.h"
#include "ost_protocol.h"
#include "pool.h"
#include "uuid.h"

#include <arpa/inet.h>

#include <errno.h>
#include <fcntl.h>
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
    } buffer;

    struct iovec iov[IOVEC_SIZE];

    int (*process)(RawstorObjectOperation *op);

    RawstorCallback *callback;

    void *data;
};


struct RawstorObject {
    int fd;
    int response_loop;
    RawstorPool *operations_pool;
    RawstorOSTFrameResponse response_frame;
};


const char *rawstor_object_backend_name = "ost";


static int response_body_received(RawstorIOEvent *event, void *data);


static int responsev_body_received(RawstorIOEvent *event, void *data);


static int operation_process_read(RawstorObjectOperation *op) {
    return rawstor_fd_recv(
        op->object->fd,
        op->buffer.linear.data, op->request_frame.len,
        response_body_received, op);
}


static int operation_process_readv(RawstorObjectOperation *op) {
    return rawstor_fd_recvv(
        op->object->fd,
        op->buffer.vector.iov, op->buffer.vector.niov, op->request_frame.len,
        responsev_body_received, op);
}


static int object_response_head_recv(RawstorObject *object);


static int operation_process_write(RawstorObjectOperation *op) {
    /**
     * Continue response loop, if there are any other pending operations.
     */
    if (rawstor_pool_allocated(op->object->operations_pool) > 1) {
        if (object_response_head_recv(op->object)) {
            rawstor_pool_free(op->object->operations_pool, op);
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    rawstor_pool_free(op->object->operations_pool, op);

    return ret;
}


static int response_head_received(RawstorIOEvent *event, void *data);


static int object_response_head_recv(RawstorObject *object) {
    if (rawstor_fd_recv(
        object->fd,
        &object->response_frame, sizeof(object->response_frame),
        response_head_received, object))
    {
        return -errno;
    }

    return 0;
}


static int socket_add_flag(int fd, int flag) {
    return 0;
    int flags = fcntl(fd, F_GETFL);
    if (flags == -1) {
        return -errno;
    }

    if (flags & flag) {
        return 0;
    }

    flags = flags | flag;
    if (fcntl(fd, F_SETFL, flags) == -1) {
        return -errno;
    }

    return 0;
}


static int ost_connect(const char *host, unsigned int port) {
    struct sockaddr_in servaddr;
    // socket create and verification
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        return -errno;
    }

    rawstor_info("Socket successfully created\n");

    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(host);
    servaddr.sin_port = htons(port);

    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        return -errno;
    }

    rawstor_info("Connected to the server\n");

    return fd;
}


static int read_request_sent(RawstorIOEvent *event, void *data) {
    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    operation_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        rawstor_pool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_pool_free(op->object->operations_pool, op);
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
        rawstor_pool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_pool_free(op->object->operations_pool, op);
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

    if (rawstor_io_event_error(event) != 0) {
        rawstor_pool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_pool_free(op->object->operations_pool, op);
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
    if (rawstor_pool_allocated(op->object->operations_pool) > 1) {
        if (object_response_head_recv(op->object)) {
            rawstor_pool_free(op->object->operations_pool, op);
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    rawstor_pool_free(op->object->operations_pool, op);

    return ret;
}


static int responsev_body_received(RawstorIOEvent *event, void *data) {
    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    operation_trace(op->cid, event);

    if (rawstor_io_event_error(event) != 0) {
        rawstor_pool_free(op->object->operations_pool, op);
        errno = rawstor_io_event_error(event);
        return -errno;
    }

    if (rawstor_io_event_result(event) != rawstor_io_event_size(event)) {
        rawstor_pool_free(op->object->operations_pool, op);
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
    if (rawstor_pool_allocated(op->object->operations_pool) > 1) {
        if (object_response_head_recv(op->object)) {
            rawstor_pool_free(op->object->operations_pool, op);
            return -errno;
        }
    } else {
        op->object->response_loop = 0;
    }

    int ret = op->callback(
        op->object,
        op->request_frame.len, op->request_frame.len, 0,
        op->data);

    rawstor_pool_free(op->object->operations_pool, op);

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
        response->cid > rawstor_pool_size(object->operations_pool)
    ) {
        /**
         * FIXME: Memory leak on used RawstorObjectOperation.
         */
        rawstor_error("Unexpected cid in response: %u\n", response->cid);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *ops = rawstor_pool_data(object->operations_pool);
    RawstorObjectOperation *op = &ops[response->cid - 1];

    operation_trace(op->cid, event);

    return op->process(op);
}


int rawstor_object_create(
    const RawstorObjectSpec RAWSTOR_UNUSED *spec,
    RawstorUUID *object_id)
{
    /**
     * TODO: Implement me.
     */
    rawstor_uuid7_init(object_id);

    return 0;
}


int rawstor_object_delete(const RawstorUUID RAWSTOR_UNUSED *object_id) {
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

    return 0;
}


int rawstor_object_open(
    const RawstorUUID *object_id,
    RawstorObject **object)
{
    const RawstorConfig *config = rawstor_config();

    RawstorObject *ret = malloc(sizeof(RawstorObject));
    if (ret == NULL) {
        return -errno;
    }
    ret->response_loop = 0;

    ret->operations_pool = rawstor_pool_create(
        QUEUE_DEPTH,
        sizeof(RawstorObjectOperation));
    if (ret->operations_pool == NULL) {
        free(ret);
        return -errno;
    }
    RawstorObjectOperation *ops = rawstor_pool_data(ret->operations_pool);
    for (unsigned int i = 0; i < QUEUE_DEPTH; ++i) {
        ops[i].cid = i + 1;
    }

    ret->fd = ost_connect(config->ost_host, config->ost_port);
    if (ret->fd < 0) {
        int errsv = -ret->fd;
        rawstor_pool_delete(ret->operations_pool);
        free(ret);
        errno = errsv;
        return -errno;
    }

    RawstorOSTFrameBasic mframe = {
        .magic = RAWSTOR_MAGIC,
        .cmd = RAWSTOR_CMD_SET_OBJECT,
    };
    memcpy(mframe.obj_id, object_id->bytes, sizeof(mframe.obj_id));
    int res = write(ret->fd, &mframe, sizeof(mframe));
    rawstor_debug("Sent request to set objid, res:%i\n", res);
    if (res < 0) {
        int errsv = errno;
        close(ret->fd);
        rawstor_pool_delete(ret->operations_pool);
        free(ret);
        errno = errsv;
        return -errno;
    }
    RawstorOSTFrameResponse rframe;
    res = read(ret->fd, &rframe, sizeof(rframe));
    if (res < 0) {
        int errsv = errno;
        close(ret->fd);
        rawstor_pool_delete(ret->operations_pool);
        free(ret);
        errno = errsv;
        return -errno;
    }
    if (rframe.magic != RAWSTOR_MAGIC) {
        rawstor_error("FATAL! Frame with wrong magic number: %x != %x\n",
                      rframe.magic, RAWSTOR_MAGIC);
        errno = EIO;
        return -errno;
    }
    rawstor_debug(
        "Response from Server: cmd:%i res:%i\n",
        rframe.cmd,
        rframe.res);

    if (socket_add_flag(ret->fd, O_NONBLOCK)) {
        int errsv = errno;
        close(ret->fd);
        rawstor_pool_delete(ret->operations_pool);
        free(ret);
        errno = errsv;
        return -errno;
    }

    *object = ret;

    return 0;
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
        "%s(): offset: = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    if (rawstor_pool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
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
        .buffer.linear.data = buf,
        // .iov
        // .message
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

    if (rawstor_pool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    if (niov >= IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
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
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        // .iov
        // .message
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

    if (rawstor_pool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .cid = op->cid,  // preserve cid
        .request_frame = (RawstorOSTFrameIO) {
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = op->cid,
            .offset = offset,
            .len = size,
            .sync = 0,
        },
        // .response_frame =
        .buffer.linear.data = buf,
        // .iov
        // .message
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
    return rawstor_fd_sendv(
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

    if (rawstor_pool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    if (niov > IOVEC_SIZE) {
        rawstor_error("Large iovecs not supported: %u", niov);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .cid = op->cid,  // preserve cid
        .request_frame = (RawstorOSTFrameIO) {
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = op->cid,
            .offset = offset,
            .len = size,
            .sync = 0,
        },
        // .response_frame =
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        // .iov
        // .message
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
    return rawstor_fd_sendv(
        object->fd,
        op->iov, niov + 1, sizeof(op->request_frame) + size,
        write_requestv_sent, op);
}
