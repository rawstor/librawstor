#include <rawstor.h>
#include <rawstor_proto.h>
#include <log.h>

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
 * FIXME: Temporary workaround for rawstor_create() and rawstor_delete()
 * methods.
 */
static struct RawstorDeviceSpec _spec;
static RawstorDevice *_device = NULL;
static char OBJ_NAME[] = "TEST_OBJ";
static int sockfd;


int rawstor_create(struct RawstorDeviceSpec spec, int *device_id) {
    assert(_device == NULL);

    _spec = spec;
    _device = malloc(_spec.size);
    *device_id = 1;

    struct sockaddr_in servaddr;
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_INFO("socket creation failed...\n");
        exit(1);
    }
    else
        LOG_INFO("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));
    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    servaddr.sin_port = htons(8080);
    // connect the client socket to server socket
    if (connect(sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr))
        != 0) {
        LOG_INFO("connection with the server failed...\n");
        exit(1);
    }
    else
        LOG_INFO("connected to the server..\n");

    char buff[8192];

    proto_basic_frame_t *mframe = malloc(sizeof(proto_basic_frame_t));
    mframe->cmd = CMD_SET_OBJECT;
    strlcpy(mframe->var, OBJ_NAME, 10);
    #if LOGLEVEL > 3
    int res = write(sockfd, mframe, sizeof(proto_basic_frame_t));
    #else
    write(sockfd, mframe, sizeof(proto_basic_frame_t));
    #endif
    LOG_DEBUG("Sent request to set objid, res:%i\n", res);
    read(sockfd, buff, sizeof(buff));
    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    memcpy(rframe, buff, sizeof(proto_resp_frame_t));
    LOG_DEBUG("Response from Server: cmd:%i res:%i\n", rframe->cmd, rframe->res);


    return 0;
}


int rawstor_delete(int device_id) {
    assert(device_id == 1);
    assert(_device != NULL);

    free(_device);
    _device = NULL;

    return 0;
}


int rawstor_open(int device_id, RawstorDevice **device) {
    assert(device_id == 1);
    assert(_device != NULL);

    *device = _device;

    return 0;
}


int rawstor_close(RawstorDevice *device) {
    assert(device != NULL);

    return 0;
}


int rawstor_spec(int device_id, struct RawstorDeviceSpec *spec) {
    assert(device_id == 1);
    assert(_device != NULL);

    *spec = _spec;

    return 0;
}

int rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    int res;
    LOG_DEBUG("readv: offset:%li size:%li niov:%i\n", offset, size, niov);
    (void)(device);
    struct msghdr msg;

    proto_io_frame_t *frame = malloc(sizeof(proto_io_frame_t));
    frame->cmd = CMD_READ;
    frame->offset = offset;
    frame->len = size;
    res = write(sockfd, frame, sizeof(proto_io_frame_t));
    LOG_DEBUG("Sent request read command offset:%li size:%li, res:%i\n", offset, size, res);

    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    read(sockfd, rframe, sizeof(proto_resp_frame_t));
    LOG_DEBUG("Read: Response from Server: cmd:%i res:%i\n", rframe->cmd, rframe->res);

    if (rframe->res != (signed)size) {
        LOG_DEBUG("Rawstor WARN: read command returned different than asked: %i != %li!\n", rframe->res, size);
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
        LOG_DEBUG("Could read less than needed: %i != %i!\n", rframe->res, res);
        exit(1);
      }
    } else {
      LOG_DEBUG("There was an error on server side, so no data for us\n");
      return rframe->res;
    }

    return 0;
}

int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    (void)(device);
    LOG_DEBUG("writev: offset:%li size:%li niov:%i\n", offset, size, niov);

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
    LOG_DEBUG("Sent request write command and data, offset:%li size:%li, res:%i\n", offset, size, res);

    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    read(sockfd, rframe, sizeof(proto_resp_frame_t));
    LOG_DEBUG("Write: Response from Server: cmd:%i res:%i\n", rframe->cmd, rframe->res);

    return 0;
}
