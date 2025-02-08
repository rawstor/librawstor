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
 * FIXME: drop OBJ_NAME.
 */
static char OBJ_NAME[] = "TEST_OBJ";


typedef struct RawstorObjectOperation {
    RawstorObject *object;
    off_t offset;

    RawstorOSTFrameIO request_frame;
    RawstorOSTFrameResponse response_frame;

    union {
        struct {
            void *data;
            size_t size;
        } linear;
        struct {
            struct iovec *iov;
            unsigned int niov;
            size_t size;
        } vector;
    } buffer;

    rawstor_linear_callback linear_callback;
    rawstor_vector_callback vector_callback;

    void *data;
} RawstorObjectOperation;


typedef struct RawstorObjectResponse {

} RawstorObjectResponse;


struct RawstorObject {
    int fd;
    RawstorPool *operations_pool;
};


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


static int response_linear_body_callback(
    int fd, off_t RAWSTOR_UNUSED offset,
    void *buf, size_t size,
    ssize_t res, void *data)
{
    if (res < 0) {
        return res;
    }

    if ((size_t)res < size) {
        return rawstor_fd_read(
            fd, 0,
            buf + res, size - res,
            response_linear_body_callback, data);
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    return op->linear_callback(
        op->object, op->offset,
        op->buffer.linear.data, op->buffer.linear.size,
        op->buffer.linear.size, op->data);
}


static int response_vector_body_callback(
    int fd, off_t RAWSTOR_UNUSED offset,
    struct iovec *iov, unsigned int niov, size_t size,
    ssize_t res, void *data)
{
    if (res < 0) {
        return res;
    }

    if ((size_t)res < size) {
        /**
         * TODO: We have to update our iov, but save original user iov.
         */
        rawstor_error("Not implemented\n");
        exit(1);
        for (unsigned int i = 0; i < niov; ++i) {
            if (iov[0].iov_len > res) {
                iov[0].iov_base += res;
                iov[0].iov_len -= res;
                size -= res;
                break;
            }
            size -= iov[0].iov_len;
            res -= iov[0].iov_len;
            ++iov;
            --niov;
        }
        return rawstor_fd_readv(
            fd, 0,
            iov, niov, size,
            response_vector_body_callback, data);
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    return op->vector_callback(
        op->object, op->offset,
        op->buffer.vector.iov, op->buffer.vector.niov, op->buffer.vector.size,
        op->buffer.vector.size, op->data);
}


static int response_header_callback(
    int fd, off_t RAWSTOR_UNUSED offset,
    void *buf, size_t size,
    ssize_t res, void *data)
{
    if (res < 0) {
        return res;
    }

    if ((size_t)res < size) {
        return rawstor_fd_read(
            fd, 0,
            buf + res, size - res,
            response_header_callback, data);
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    rawstor_debug(
        "Read: Response from Server: cmd:%i res:%i\n",
        op->response_frame.cmd,
        op->response_frame.res);

    if ((size_t)op->response_frame.res
        != op->buffer.linear.size)
    {
        rawstor_warning(
            "read command returned different than asked: "
            "%i != %li!\n",
            op->response_frame.res,
            op->buffer.linear.size);
        /**
         * TODO: Find proper error here.
         */
        return -1;
    }

    return op->linear_callback != NULL ?
        rawstor_fd_read(
            fd, 0,
            op->buffer.linear.data, op->buffer.linear.size,
            response_linear_body_callback, op) :
        rawstor_fd_readv(
            fd, 0,
            op->buffer.vector.iov,
            op->buffer.vector.niov,
            op->buffer.vector.size,
            response_vector_body_callback, op);
}


static int request_callback(
    int fd, off_t RAWSTOR_UNUSED offset,
    void *buf, size_t size,
    ssize_t res, void *data)
{
    if (res < 0) {
        return res;
    }

    if ((size_t)res < size) {
        return rawstor_fd_write(
            fd, 0,
            buf + res, size - res,
            request_callback, data);
    }

    RawstorObjectOperation *op = (RawstorObjectOperation*)data;

    rawstor_debug(
        "Sent request read command offset:%lli, size:%u, res:%zi\n",
        op->request_frame.offset,
        op->request_frame.len,
        res);

    return rawstor_fd_read(
        fd, 0,
        &op->response_frame, sizeof(op->response_frame),
        response_header_callback, op);
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
        rawstor_pool_delete(ret->operations_pool);
        free(ret);
        return ret->fd;
    }

    char buff[8192];

    RawstorOSTFrameBasic *mframe = malloc(sizeof(RawstorOSTFrameBasic));
    mframe->cmd = CMD_SET_OBJECT;
    strlcpy(mframe->var, OBJ_NAME, 10);
    #if LOGLEVEL > 3
    int res = write(ret->fd, mframe, sizeof(RawstorOSTFrameBasic));
    rawstor_debug("Sent request to set objid, res:%i\n", res);
    #else
    write(ret->fd, mframe, sizeof(RawstorOSTFrameBasic));
    #endif
    read(ret->fd, buff, sizeof(buff));
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
    rawstor_linear_callback cb, void *data)
{
    rawstor_debug("read: offset:%lli size:%li\n", offset, size);

    if (rawstor_pool_count(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .request_frame = (RawstorOSTFrameIO) {
            .cmd = CMD_READ,
            .offset = offset,
            .len = size,
        },
        .buffer.linear.data = buf,
        .buffer.linear.size = size,
        .linear_callback = cb,
        .vector_callback = NULL,
        .data = data,
    };

    return rawstor_fd_write(
        object->fd, 0,
        &op->request_frame, sizeof(op->request_frame),
        request_callback, op);
}


int rawstor_object_readv(
    RawstorObject *object, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data)
{
    rawstor_debug("readv: offset:%lli size:%li niov:%i\n", offset, size, niov);

    if (rawstor_pool_count(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }

    RawstorObjectOperation *op = rawstor_pool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .offset = 0,
        .request_frame = (RawstorOSTFrameIO) {
            .cmd = CMD_READ,
            .offset = offset,
            .len = size,
        },
        // .response_frame
        .buffer.vector.iov = iov,
        .buffer.vector.niov = niov,
        .buffer.vector.size = size,
        .linear_callback = NULL,
        .vector_callback = cb,
        .data = data,
    };

    return rawstor_fd_write(
        object->fd, 0,
        &op->request_frame, sizeof(op->request_frame),
        request_callback, op);
}


int rawstor_object_write(
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_linear_callback cb, void *data)
{
    rawstor_debug("write: offset:%lld size:%li\n", offset, size);

    RawstorOSTFrameIO *frame = malloc(sizeof(RawstorOSTFrameIO));
    if (frame == NULL) {
        return -errno;
    }
    frame->cmd = CMD_WRITE;
    frame->offset = offset;
    frame->len = size;
    frame->sync = 0;

    //hack to prepend command frame
    struct iovec miovecs[2];

    miovecs[0].iov_base = frame;
    miovecs[0].iov_len = sizeof(RawstorOSTFrameIO);

    miovecs[1].iov_base = buf;
    miovecs[1].iov_len = size;

    ssize_t res = writev(object->fd, miovecs, 2);
    if (res < 0) {
        free(frame);
        return -errno;
    }
    rawstor_debug(
        "Sent request write command and data, offset:%lld size:%li, res:%zu\n",
        offset,
        size,
        res);

    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    if (rframe == NULL) {
        free(frame);
        return -errno;
    }
    read(object->fd, rframe, sizeof(RawstorOSTFrameResponse));
    // TODO: handle read rval ^^^
    rawstor_debug(
        "Write: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    res = rframe->res;

    free(frame);
    free(rframe);

    cb(object, offset, buf, size, res, data);

    return 0;
}


int rawstor_object_writev(
    RawstorObject *object,
    off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data)
{
    rawstor_debug("writev: offset:%lld size:%li niov:%i\n", offset, size, niov);

    RawstorOSTFrameIO *frame = malloc(sizeof(RawstorOSTFrameIO));
    if (frame == NULL) {
        return -errno;
    }
    frame->cmd = CMD_WRITE;
    frame->offset = offset;
    frame->len = size;
    frame->sync = 0;

    //hack to prepend command frame
    struct iovec miovecs[niov+1];

    for (size_t i = 0; i < niov; ++i) {
        miovecs[i+1].iov_base = iov[i].iov_base;
        miovecs[i+1].iov_len = iov[i].iov_len;
    }

    miovecs[0].iov_base = frame;
    miovecs[0].iov_len = sizeof(RawstorOSTFrameIO);

    ssize_t res = writev(object->fd, miovecs, niov + 1);
    if (res < 0) {
        free(frame);
        return -errno;
    }
    rawstor_debug(
        "Sent request write command and data, offset:%lld size:%li, res:%zu\n",
        offset,
        size,
        res);

    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    if (rframe == NULL) {
        free(frame);
        return -errno;
    }
    read(object->fd, rframe, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Write: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    res = rframe->res;

    free(frame);
    free(rframe);

    cb(object, offset, iov, niov, size, res, data);

    return 0;
}
