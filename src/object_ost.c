#include <rawstor.h>

#include "gcc.h"
#include "logging.h"
#include "ost_protocol.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <stdio.h>
#include <strings.h>
#include <unistd.h>


/**
 * FIXME: drop OBJ_NAME.
 */
static char OBJ_NAME[] = "TEST_OBJ";


struct RawstorObject {
    int sockfd;
};


int rawstor_object_create(
    struct RawstorObjectSpec RAWSTOR_UNUSED spec,
    int *object_id)
{
    struct sockaddr_in servaddr;
    // socket create and verification
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        rawstor_info("socket creation failed...\n");
        exit(1);
    }
    else
        rawstor_info("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8080);
    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        != 0) {
        rawstor_info("connection with the server failed...\n");
        exit(1);
    }
    else
        rawstor_info("connected to the server..\n");

    char buff[8192];

    proto_basic_frame_t *mframe = malloc(sizeof(proto_basic_frame_t));
    mframe->cmd = CMD_SET_OBJECT;
    strlcpy(mframe->var, OBJ_NAME, 10);
    #if LOGLEVEL > 3
    int res = write(sockfd, mframe, sizeof(proto_basic_frame_t));
    rawstor_debug("Sent request to set objid, res:%i\n", res);
    #else
    write(sockfd, mframe, sizeof(proto_basic_frame_t));
    #endif
    read(sockfd, buff, sizeof(buff));
    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    memcpy(rframe, buff, sizeof(proto_resp_frame_t));
    rawstor_debug(
        "Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    /**
     * FIXME: return real object id.
     */
    *object_id = 1;

    return 0;
}


int rawstor_object_delete(int RAWSTOR_UNUSED object_id) {
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

    return 0;
}


int rawstor_open(int device_id, RawstorObject **object) {
    assert(device_id == 1);
    assert(_device != NULL);

    *object = _device;

    return 0;
}


int rawstor_close(RawstorObject *object) {
    assert(object != NULL);

    return 0;
}


int rawstor_spec(int device_id, struct RawstorObjectSpec *spec) {
    assert(device_id == 1);
    assert(_device != NULL);

    *spec = _spec;

    return 0;
}

int rawstor_readv(
    RawstorObject RAWSTOR_UNUSED *object,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    int res;
    rawstor_debug("readv: offset:%li size:%li niov:%i\n", offset, size, niov);
    struct msghdr msg;

    proto_io_frame_t *frame = malloc(sizeof(proto_io_frame_t));
    frame->cmd = CMD_READ;
    frame->offset = offset;
    frame->len = size;
    res = write(sockfd, frame, sizeof(proto_io_frame_t));
    rawstor_debug(
        "Sent request read command offset:%li size:%li, res:%i\n",
        offset,
        size,
        res);

    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    read(sockfd, rframe, sizeof(proto_resp_frame_t));
    rawstor_debug(
        "Read: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    if (rframe->res != (signed)size) {
        rawstor_debug(
            "Rawstor WARN: read command returned different than asked: "
            "%i != %li!\n",
            rframe->res,
            size);
        exit(1);
    }

    if (rframe->res >= 0) {
      msg.msg_iov = iov;
      msg.msg_iovlen = niov;
      res = recvmsg(sockfd, &msg, MSG_WAITALL);
      if (res<=0) {
        perror("read");
        exit(1);
      }
      if (res != rframe->res) {
        rawstor_debug(
            "Could not read less than needed: %i != %i!\n",
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


    return 0;
}

int rawstor_writev(
    RawstorObject RAWSTOR_UNUSED *object,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    rawstor_debug("writev: offset:%li size:%li niov:%i\n", offset, size, niov);

    proto_io_frame_t *frame = malloc(sizeof(proto_io_frame_t));
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
    miovecs[0].iov_len = sizeof(proto_io_frame_t);

    int res = writev(sockfd, miovecs, niov+1);
    if (res<=0) {
        perror("writev");
        exit(1);
    }
    rawstor_debug(
        "Sent request write command and data, offset:%li size:%li, res:%i\n",
        offset,
        size,
        res);

    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    read(sockfd, rframe, sizeof(proto_resp_frame_t));
    rawstor_debug(
        "Write: Response from Server: cmd:%i res:%i\n",
        rframe->cmd,
        rframe->res);

    free(frame);
    free(rframe);

    return 0;
}
