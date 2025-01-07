#include "rawstor.h"
#include "rawstor_proto.h"
#include "log.h"

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
static RawstorDeviceSpec _spec;
static RawstorDevice *_device = NULL;
static char OBJ_NAME[] = "TEST_OBJ";
static int sockfd;


int rawstor_create(RawstorDeviceSpec spec, int *device_id) {
    assert(_device == NULL);

    _spec = spec;
    _device = malloc(_spec.size);
    *device_id = 1;

    struct sockaddr_in servaddr;
    // socket create and verification
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd == -1) {
        LOG_INFO("socket creation failed...\n");
        exit(0);
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
        exit(0);
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


int rawstor_spec(int device_id, RawstorDeviceSpec *spec) {
    assert(device_id == 1);
    assert(_device != NULL);

    *spec = _spec;

    return 0;
}


int rawstor_read(
    RawstorDevice *device,
    size_t offset, size_t size,
    void *buf)
{
    (void)(device);

    proto_io_frame_t *frame = malloc(sizeof(proto_io_frame_t));
    frame->cmd = CMD_READ;
    frame->offset = offset;
    frame->len = (u_int16_t)size;
    int res = write(sockfd, frame, sizeof(proto_io_frame_t));
    LOG_DEBUG("Sent request read command offset:%li size:%li, res:%i\n", offset, size, res);

    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    read(sockfd, rframe, sizeof(proto_resp_frame_t));
    LOG_DEBUG("Read: Response from Server: cmd:%i res:%i\n", rframe->cmd, rframe->res);

    if (rframe->res >= 0) {
      res = read(sockfd, buf, rframe->res);
      if (res<0) {
        perror("read");
        return res;
      }
    } else {
      LOG_DEBUG("There was an error on server side, so no data for us\n");
      return rframe->res;
    }

    if (rframe->res != (signed)size) {
        LOG_DEBUG("Rawstor WARN: read command returned less than asked: %i != %li!\n", rframe->res, size);
    }

    return 0;
}


int rawstor_readv(
    RawstorDevice *device,
    size_t offset, size_t size,
    struct iovec *iov, unsigned int niov)
{
    int res;
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        res = rawstor_read(device, offset, chunk_size, iov[i].iov_base);
        if (res<0) {
            return res;
        }

        size -= chunk_size;
        offset += chunk_size;
    }

    return 0;
}


int rawstor_write(
    RawstorDevice *device,
    size_t offset, size_t size,
    const void *buf)
{
    (void)(device);

    proto_io_w_frame_t *frame = malloc(sizeof(proto_io_w_frame_t));
    frame->cmd = CMD_WRITE;
    frame->offset = offset;
    frame->len = (u_int16_t)size;
    frame->sync = 0;

    struct iovec iovecs[2];

    iovecs[0].iov_base = frame;
    iovecs[0].iov_len = sizeof(proto_io_w_frame_t);

    iovecs[1].iov_base = (void *)buf;
    iovecs[1].iov_len = size;

    int res = writev(sockfd, iovecs, 2);
    if (res<0) {
        perror("writev");
        return res;
    }
    LOG_DEBUG("Sent request write command and data, offset:%li size:%li, res:%i\n", offset, size, res);


    proto_resp_frame_t *rframe = malloc(sizeof(proto_resp_frame_t));
    read(sockfd, rframe, sizeof(proto_resp_frame_t));
    LOG_DEBUG("Write: Response from Server: cmd:%i res:%i\n", rframe->cmd, rframe->res);

    return rframe->res;
}


int rawstor_writev(
    RawstorDevice *device,
    size_t offset, size_t size,
    const struct iovec *iov, unsigned int niov)
{
    int res;
    for (unsigned int i = 0; i < niov; ++i) {
        size_t chunk_size = size < iov[i].iov_len ? size : iov[i].iov_len;

        res = rawstor_write(device, offset, chunk_size, iov[i].iov_base);
        if (res<0) {
            return res;
        }

        size -= chunk_size;
        offset += chunk_size;
    }

    return 0;
}
