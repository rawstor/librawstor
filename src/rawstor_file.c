#include <rawstor.h>

#include "aio.h"

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define RAWSTOR_PATH "/tmp"


typedef struct RawstorDevice {
    int fd;
} RawstorDevice;


int rawstor_create(struct RawstorDeviceSpec spec, int *device_id) {
    char path[1024];
    int fd;
    int id = 1;
    while (1) {
        snprintf(path, sizeof(path), RAWSTOR_PATH "/rawstor-%d", id);

        fd = open(path, O_EXCL | O_CREAT | O_WRONLY);
        if (fd != -1) {
            break;
        }
        if (errno != EEXIST) {
            return -errno;
        }
        ++id;
    }
    close(fd);
    *device_id = id;

    snprintf(path, sizeof(path), RAWSTOR_PATH "/rawstor-%d.spec", id);
    fd = open(path, O_CREAT | O_WRONLY);
    if (fd == -1) {
        return -errno;
    }
    ssize_t rval = write(fd, &spec, sizeof(spec));
    if (rval == -1) {
        int errsv = errno;
        close(fd);
        errno = errsv;
        return -errno;
    }
    close(fd);

    return 0;
}


int rawstor_delete(int device_id) {
    int rval;
    char path[1024];

    snprintf(path, sizeof(path), RAWSTOR_PATH "/rawstor-%d", device_id);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }

    snprintf(path, sizeof(path), RAWSTOR_PATH "/rawstor-%d.spec", device_id);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }
    return 0;
}


int rawstor_open(int device_id, RawstorDevice **device) {
    RawstorDevice *rd = malloc(sizeof(RawstorDevice));
    if (rd == NULL) {
        return -errno;
    }

    char path[1024];
    snprintf(path, sizeof(path), RAWSTOR_PATH "/rawstor-%d", device_id);
    rd->fd = open(path, O_RDWR);
    if (rd->fd == -1) {
        int errsv = errno;
        free(rd);
        errno = errsv;
        return -errno;
    }

    *device = rd;

    return 0;
}


int rawstor_close(RawstorDevice *device) {
    int rval = close(device->fd);
    if (rval == -1) {
        return -errno;
    }

    free(device);

    return 0;
}


int rawstor_spec(int device_id, struct RawstorDeviceSpec *spec) {
    char path[1024];

    snprintf(path, sizeof(path), RAWSTOR_PATH "/rawstor-%d.spec", device_id);
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        return -errno;
    }
    ssize_t rval = read(fd, spec, sizeof(*spec));
    if (rval == -1) {
        int errsv = errno;
        close(fd);
        errno = errsv;
        return -errno;
    }
    close(fd);
    return 0;
}


int rawstor_read(
    RawstorDevice *device,
    size_t offset,
    void *buf, size_t size)
{
    RawstorAIOEvent *event = rawstor_fd_read(
        device->fd, offset,
        buf, size);
    if (event == NULL) {
        return -1;
    }
    rawstor_aio_event_set_data(event, device);

    return 0;
}


int rawstor_readv(
    RawstorDevice *device,
    size_t offset,
    struct iovec *iov, unsigned int niov)
{
    RawstorAIOEvent *event = rawstor_fd_readv(
        device->fd, offset,
        iov, niov);
    if (event == NULL) {
        return -1;
    }
    rawstor_aio_event_set_data(event, device);

    return 0;
}


int rawstor_write(
    RawstorDevice *device,
    size_t offset,
    void *buf, size_t size)
{
    RawstorAIOEvent *event = rawstor_fd_read(
        device->fd, offset,
        buf, size);
    if (event == NULL) {
        return -1;
    }
    rawstor_aio_event_set_data(event, device);

    return 0;
}


int rawstor_writev(
    RawstorDevice *device,
    size_t offset,
    struct iovec *iov, unsigned int niov)
{
    RawstorAIOEvent *event = rawstor_fd_writev(
        device->fd, offset,
        iov, niov);
    if (event == NULL) {
        return -1;
    }
    rawstor_aio_event_set_data(event, device);

    return 0;
}
