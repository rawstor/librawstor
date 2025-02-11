#include <rawstor.h>

#include "aio.h"
#include "gcc.h"
#include "logging.h"
#include "ost_protocol.h"
#include "pool.h"

#include <arpa/inet.h>

#include <sys/socket.h>

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


/**
 * FIXME: drop OBJ_NAME.
 */
static char OBJ_NAME[] = "TEST_OBJ";


#define rawstor_operation_trace(fd, res, size) \
    rawstor_debug("[%d] %s(): %zi of %zu\n", fd, __FUNCTION__, res, size)


typedef struct RawstorObjectOperation {
    RawstorObject *object;

    RawstorOSTFrameIO request_frame;
    RawstorOSTFrameResponse response_frame;

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
    struct msghdr message;

    rawstor_callback linear_callback;
    rawstor_vector_callback vector_callback;

    void *data;
} RawstorObjectOperation;


typedef struct RawstorObjectResponse {

} RawstorObjectResponse;


struct RawstorObject {
    int fd;
    RawstorPool *operations_pool;
};


const char *rawstor_object_backend_name = "ost";


static int ost_connect() {
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
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8080);

    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))) {
        return -errno;
    }

    rawstor_info("Connected to the server\n");

    return fd;
}


static int read_response_body_received(
    int fd, off_t RAWSTOR_UNUSED offset,
    void RAWSTOR_UNUSED *buf, size_t size,
    ssize_t res, void *data)
{
    rawstor_operation_trace(fd, res, size);

    if (res < 0) {
        return res;
    }

    if ((size_t)res != size) {
        rawstor_error(
            "Response body size mismatch: %zu != %zu\n",
            (size_t)res, size);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    int ret = op->linear_callback(
        op->object, op->request_frame.offset,
        op->buffer.linear.data, op->request_frame.len,
        op->request_frame.len, op->data);

    rawstor_pool_free(op->object->operations_pool, op);

    return ret;
}


static int read_responsev_body_received(
    int fd, off_t RAWSTOR_UNUSED offset,
    struct iovec RAWSTOR_UNUSED *iov, unsigned int RAWSTOR_UNUSED niov,
    size_t size,
    ssize_t res, void *data)
{
    rawstor_operation_trace(fd, res, size);

    if (res < 0) {
        return res;
    }

    if ((size_t)res != size) {
        rawstor_error(
            "Response body size mismatch: %zu != %zu\n",
            (size_t)res, size);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    int ret = op->vector_callback(
        op->object, op->request_frame.offset,
        op->buffer.vector.iov, op->buffer.vector.niov, op->request_frame.len,
        op->request_frame.len, op->data);

    rawstor_pool_free(op->object->operations_pool, op);

    return ret;
}


static int read_response_header_received(
    int fd, off_t RAWSTOR_UNUSED offset,
    void RAWSTOR_UNUSED *buf, size_t size,
    ssize_t res, void *data)
{
    rawstor_operation_trace(fd, res, size);

    if (res < 0) {
        return res;
    }

    if ((size_t)res != size) {
        rawstor_error(
            "Response header size mismatch: %zu != %zu\n",
            (size_t)res, size);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    if ((u_int32_t)op->response_frame.res != op->request_frame.len) {
        rawstor_warning(
            "read command returned different than asked: "
            "%d != %d!\n",
            op->response_frame.res,
            op->request_frame.len);
        /**
         * TODO: Find proper error here.
         */
        return -1;
    }

    if (op->linear_callback != NULL) {
        return rawstor_sock_recv(
            fd, MSG_WAITALL,
            op->buffer.linear.data, op->request_frame.len,
            read_response_body_received, op);
    } else {
        op->message = (struct msghdr) {
            .msg_iov = op->buffer.vector.iov,
            .msg_iovlen = op->buffer.vector.niov,
        };
        return rawstor_sock_recvmsg(
            fd, MSG_WAITALL,
            &op->message, op->request_frame.len,
            read_responsev_body_received, op);
    }
}


static int read_request_sent(
    int fd, off_t RAWSTOR_UNUSED offset,
    void *buf, size_t size,
    ssize_t res, void *data)
{
    rawstor_operation_trace(fd, res, size);

    if (res < 0) {
        return res;
    }

    if ((size_t)res < size) {
        return rawstor_fd_write(
            fd, 0,
            buf + res, size - res,
            read_request_sent, data);
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    return rawstor_sock_recv(
        fd, MSG_WAITALL,
        &op->response_frame, sizeof(op->response_frame),
        read_response_header_received, op);
}


static int write_response_received(
    int fd, off_t RAWSTOR_UNUSED offset,
    void RAWSTOR_UNUSED *buf, size_t size,
    ssize_t res, void *data)
{
    rawstor_operation_trace(fd, res, size);

    if (res < 0) {
        return res;
    }

    if ((size_t)res != size) {
        rawstor_error(
            "Response header size mismatch: %zu != %zu\n",
            (size_t)res, size);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    int ret = op->linear_callback != NULL ?
        op->linear_callback(
            op->object, op->request_frame.offset,
            op->buffer.linear.data, op->request_frame.len,
            op->request_frame.len, op->data
        ) :
        op->vector_callback(
            op->object, op->request_frame.offset,
            op->buffer.vector.iov, op->buffer.vector.niov,
            op->request_frame.len,
            op->request_frame.len, op->data
        );

    rawstor_pool_free(op->object->operations_pool, op);

    return ret;
}


static int write_request_sent(
    int fd, off_t RAWSTOR_UNUSED offset,
    struct iovec RAWSTOR_UNUSED *iov, unsigned int RAWSTOR_UNUSED niov,
    size_t size,
    ssize_t res, void *data)
{
    rawstor_operation_trace(fd, res, size);

    if (res < 0) {
        return res;
    }

    if ((size_t)res != size) {
        rawstor_error(
            "Request size mismatch: %zu != %zu\n",
            (size_t)res, size);
        errno = EIO;
        return -errno;
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    return rawstor_sock_recv(
        fd, MSG_WAITALL,
        &op->response_frame, sizeof(op->response_frame),
        write_response_received, op);
}


int rawstor_object_create(
    struct RawstorObjectSpec RAWSTOR_UNUSED spec,
    int *object_id)
{
    /**
     * TODO: Implement me.
     */
    *object_id = 1;

    return 0;
}


int rawstor_object_delete(int RAWSTOR_UNUSED object_id) {
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

    return 0;
}


int rawstor_object_open(int RAWSTOR_UNUSED object_id, RawstorObject **object) {
    RawstorObject *ret = malloc(sizeof(RawstorObject));
    if (ret == NULL) {
        return -errno;
    }

    ret->operations_pool = rawstor_pool_create(
        QUEUE_DEPTH,
        sizeof(RawstorObjectOperation));
    if (ret->operations_pool == NULL) {
        free(ret);
        return -errno;
    }

    ret->fd = ost_connect();
    if (ret->fd < 0) {
        int errsv = -ret->fd;
        rawstor_pool_delete(ret->operations_pool);
        free(ret);
        errno = errsv;
        return -errno;
    }

    char buff[8192];

    RawstorOSTFrameBasic *mframe = malloc(sizeof(RawstorOSTFrameBasic));
    mframe->cmd = RAWSTOR_CMD_SET_OBJECT;
    strlcpy(mframe->obj_id, OBJ_NAME, OBJID_LEN);
    int res = write(ret->fd, mframe, sizeof(RawstorOSTFrameBasic));
    rawstor_debug("Sent request to set objid, res:%i\n", res);
    if (res < 0) {
        free(ret);
        return -errno;
    }
    res = read(ret->fd, buff, sizeof(buff));
    if (res < 0) {
        free(ret);
        return -errno;
    }
    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    memcpy(rframe, buff, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

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
    int RAWSTOR_UNUSED object_id,
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


int rawstor_object_read(
    RawstorObject *object, off_t offset,
    void *buf, size_t size,
    rawstor_callback cb, void *data)
{
    rawstor_debug(
        "[%d] %s(): offset: = %jd, size = %zu\n",
        object->fd, __FUNCTION__, (intmax_t)offset, size);

    if (rawstor_pool_count(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .request_frame = (RawstorOSTFrameIO) {
            .cmd = RAWSTOR_CMD_READ,
            .cid = 0,
            .offset = offset,
            .len = size,
            .sync = 0,
        },
        // .response_frame =
        .buffer.linear.data = buf,
        .linear_callback = cb,
        .vector_callback = NULL,
        .data = data,
    };

    return rawstor_fd_write(
        object->fd, 0,
        &op->request_frame, sizeof(op->request_frame),
        read_request_sent, op);
}


int rawstor_object_readv(
    RawstorObject *object, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data)
{
    rawstor_debug(
        "[%d] %s(): offset = %jd, niov = %u, size = %zu\n",
        object->fd, __FUNCTION__, (intmax_t)offset, niov, size);

    if (rawstor_pool_count(object->operations_pool) == 0) {
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
        .request_frame = (RawstorOSTFrameIO) {
            .cmd = RAWSTOR_CMD_READ,
            .cid = 0,
            .offset = offset,
            .len = size,
        },
        // .response_frame
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .linear_callback = NULL,
        .vector_callback = cb,
        .data = data,
    };

    return rawstor_fd_write(
        object->fd, 0,
        &op->request_frame, sizeof(op->request_frame),
        read_request_sent, op);
}


int rawstor_object_write(
    RawstorObject *object, off_t offset,
    void *buf, size_t size,
    rawstor_callback cb, void *data)
{
     rawstor_debug(
        "[%d] %s(): offset = %jd, size = %zu\n",
        object->fd, __FUNCTION__, (intmax_t)offset, size);

    if (rawstor_pool_count(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .request_frame = (RawstorOSTFrameIO) {
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = 0,
            .offset = offset,
            .len = size,
            .sync = 0,
        },
        // .response_frame =
        .buffer.linear.data = buf,
        .linear_callback = cb,
        .vector_callback = NULL,
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
    op->message = (struct msghdr) {
        .msg_iov = op->iov,
        .msg_iovlen = 2,
    };
    return rawstor_sock_sendmsg(
        object->fd, 0,
        &op->message, sizeof(op->request_frame) + size,
        write_request_sent, op);
}


int rawstor_object_writev(
    RawstorObject *object, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data)
{
    rawstor_debug(
        "[%d] %s(): offset = %jd, niov = %u, size = %zu\n",
        object->fd, __FUNCTION__, (intmax_t)offset, niov, size);

    if (rawstor_pool_count(object->operations_pool) == 0) {
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
        .request_frame = (RawstorOSTFrameIO) {
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = 0,
            .offset = offset,
            .len = size,
            .sync = 0,
        },
        // .response_frame =
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .linear_callback = NULL,
        .vector_callback = cb,
        .data = data,
    };

    op->iov[0] = (struct iovec) {
        .iov_base = &op->request_frame,
        .iov_len = sizeof(op->request_frame),
    };
    for (unsigned int i = 0; i < niov; ++i) {
        op->iov[i + 1] = iov[i];
    }
    op->message = (struct msghdr) {
        .msg_iov = op->iov,
        .msg_iovlen = niov + 1,
    };
    return rawstor_sock_sendmsg(
        object->fd, 0,
        &op->message, sizeof(op->request_frame) + size,
        write_request_sent, op);
}
