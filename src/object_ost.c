#include <rawstor.h>

#include "gcc.h"
#include "logging.h"
#include "ost_protocol.h"

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
 * FIXME: drop OBJ_NAME.
 */
static char OBJ_NAME[] = "TEST_OBJ";


struct RawstorObject {
    int fd;
};


static int ost_connect() {
    struct sockaddr_in servaddr;
    // socket create and verification
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        rawstor_info("socket creation failed...\n");
        exit(1);
    } else {
        rawstor_info("Socket successfully created..\n");
    }
    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8080);
    // connect the client socket to server socket
    if (connect(fd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        != 0) {
        rawstor_info("connection with the server failed...\n");
        exit(1);
    } else {
        rawstor_info("connected to the server..\n");
    }

    return fd;
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
    int fd = ost_connect();

    char buff[8192];

    RawstorOSTFrameBasic *mframe = malloc(sizeof(RawstorOSTFrameBasic));
    mframe->cmd = CMD_SET_OBJECT;
    strlcpy(mframe->var, OBJ_NAME, 10);
    #if LOGLEVEL > 3
    int res = write(fd, mframe, sizeof(RawstorOSTFrameBasic));
    rawstor_debug("Sent request to set objid, res:%i\n", res);
    #else
    write(fd, mframe, sizeof(RawstorOSTFrameBasic));
    #endif
    read(fd, buff, sizeof(buff));
    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    memcpy(rframe, buff, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    RawstorObject *ret = malloc(sizeof(RawstorObject));
    ret->fd = fd;

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
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_linear_callback cb, void *data)
{
    ssize_t res;
    rawstor_debug("read: offset:%lli size:%li\n", offset, size);
    struct msghdr msg;
    struct iovec iov;

    RawstorOSTFrameIO *frame = malloc(sizeof(RawstorOSTFrameIO));
    frame->cmd = CMD_READ;
    frame->offset = offset;
    frame->len = size;
    res = write(object->fd, frame, sizeof(RawstorOSTFrameIO));
    rawstor_debug(
        "Sent request read command offset:%lli size:%li, res:%zi\n",
        offset,
        size,
        res);

    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    res = read(object->fd, rframe, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Read: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    if (rframe->res != (signed)size) {
        rawstor_warning(
            "read command returned different than asked: "
            "%i != %li!\n",
            rframe->res,
            size);
        exit(1);
    }

    if (rframe->res >= 0) {
        iov.iov_base = buf;
        iov.iov_len = size;
        msg.msg_iov = &iov;
        msg.msg_iovlen = 1;
        res = recvmsg(object->fd, &msg, MSG_WAITALL);
        if (res<=0) {
            perror("read");
            exit(1);
        }
        if (res != rframe->res) {
            rawstor_debug(
                "Could not read less than needed: %i != %zi!\n",
                rframe->res,
                res);
            exit(1);
        }
    } else {
      // TODO: handle this case
      rawstor_debug("There was an error on server side, so no data for us\n");
      exit(1);
    }

    free(frame);
    free(rframe);

    cb(object, offset, buf, size, res, data);

    return 0;
}


int rawstor_object_readv(
    RawstorObject *object, off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_callback cb, void *data)
{
    ssize_t res;
    rawstor_debug("readv: offset:%lli size:%li niov:%i\n", offset, size, niov);
    struct msghdr msg;

    RawstorOSTFrameIO *frame = malloc(sizeof(RawstorOSTFrameIO));
    frame->cmd = CMD_READ;
    frame->offset = offset;
    frame->len = size;
    res = write(object->fd, frame, sizeof(RawstorOSTFrameIO));
    rawstor_debug(
        "Sent request read command offset:%lli size:%li, res:%zi\n",
        offset,
        size,
        res);

    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    res = read(object->fd, rframe, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Read: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    if (rframe->res != (signed)size) {
        rawstor_warning(
            "read command returned different than asked: "
            "%i != %li!\n",
            rframe->res,
            size);
        exit(1);
    }

    if (rframe->res >= 0) {
        msg.msg_iov = iov;
        msg.msg_iovlen = niov;
        res = recvmsg(object->fd, &msg, MSG_WAITALL);
        if (res<=0) {
            perror("read");
            exit(1);
        }
        if (res != rframe->res) {
            rawstor_debug(
                "Could not read less than needed: %i != %zi!\n",
                rframe->res,
                res);
            exit(1);
        }
    } else {
      // TODO: handle this case
      rawstor_debug("There was an error on server side, so no data for us\n");
      exit(1);
    }

    free(frame);
    free(rframe);

    cb(object, offset, iov, niov, size, res, data);

    return 0;
}


int rawstor_object_write(
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_linear_callback cb, void *data)
{
    rawstor_debug("write: offset:%lld size:%li", offset, size);

    RawstorOSTFrameIO *frame = malloc(sizeof(RawstorOSTFrameIO));
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
    if (res <= 0) {
        perror("writev");
        exit(1);
    }
    rawstor_debug(
        "Sent request write command and data, offset:%lld size:%li, res:%zu\n",
        offset,
        size,
        res);

    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    read(object->fd, rframe, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Write: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

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
    frame->cmd = CMD_WRITE;
    frame->offset = offset;
    frame->len = size;
    frame->sync = 0;

    //hack to prepend command frame
    struct iovec miovecs[niov+1];

    for (size_t i = 0; i < niov; i++) {
        miovecs[i+1].iov_base = iov[i].iov_base;
        miovecs[i+1].iov_len = iov[i].iov_len;
    }

    miovecs[0].iov_base = frame;
    miovecs[0].iov_len = sizeof(RawstorOSTFrameIO);

    ssize_t res = writev(object->fd, miovecs, niov+1);
    if (res<=0) {
        perror("writev");
        exit(1);
    }
    rawstor_debug(
        "Sent request write command and data, offset:%lld size:%li, res:%zu\n",
        offset,
        size,
        res);

    RawstorOSTFrameResponse *rframe = malloc(sizeof(RawstorOSTFrameResponse));
    read(object->fd, rframe, sizeof(RawstorOSTFrameResponse));
    rawstor_debug(
        "Write: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    free(frame);
    free(rframe);

    cb(object, offset, iov, niov, size, res, data);

    return 0;
}
