#include <rawstor.h>

#include "aio.h"
#include "stack_buffer.h"

#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


#define PREFIX "."


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


typedef struct RawstorVolumeTransaction {
    RawstorVolume *volume;
    rawstor_cb cb;
    void *data;
} RawstorVolumeTransaction;


typedef struct RawstorVolume {
    int fd;
    RawstorSB *transactions_buffer;
} RawstorVolume;


static int aio_cb(RawstorAIOEvent *, void *data) {
    RawstorVolumeTransaction *t = data;
    int rval = t->cb(t->volume, t->data);
    rawstor_sb_release(t->volume->transactions_buffer, t);
    return rval;
}


int rawstor_create(struct RawstorVolumeSpec spec, int *volume_id) {
    char spec_path[1024];
    int fd;
    int id = 1;
    while (1) {
        snprintf(spec_path, sizeof(spec_path), PREFIX "/rawstor-%d.spec", id);
        fd = open(spec_path, O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            break;
        }
        if (errno != EEXIST) {
            return -errno;
        }

        ++id;
    }
    ssize_t rval = write(fd, &spec, sizeof(spec));
    if (rval == -1) {
        int errsv = errno;
        close(fd);
        errno = errsv;
        return -errno;
    }
    close(fd);

    char dat_path[1024];
    snprintf(dat_path, sizeof(dat_path), PREFIX "/rawstor-%d.dat", id);
    fd = open(dat_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        int errsv = errno;
        unlink(spec_path);
        errno = errsv;
        return -errno;
    }
    rval = ftruncate(fd, spec.size);
    if (rval) {
        int errsv = errno;
        close(fd);
        unlink(dat_path);
        unlink(spec_path);
        errno = errsv;
        return -errno;
    }
    close(fd);

    *volume_id = id;

    return 0;
}


int rawstor_delete(int volume_id) {
    int rval;
    char path[1024];

    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.spec", volume_id);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }

    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.dat", volume_id);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }
    return 0;
}


int rawstor_open(int volume_id, RawstorVolume **volume) {
    RawstorVolume *rd = malloc(sizeof(RawstorVolume));
    if (rd == NULL) {
        return -errno;
    }

    rd->transactions_buffer = rawstor_sb_create(
        QUEUE_DEPTH,
        sizeof(RawstorVolumeTransaction));
    if (rd->transactions_buffer == NULL) {
        free(rd);
        return -errno;
    }

    char path[1024];
    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.dat", volume_id);
    rd->fd = open(path, O_RDWR);
    if (rd->fd == -1) {
        int errsv = errno;
        free(rd);
        errno = errsv;
        return -errno;
    }

    *volume = rd;

    return 0;
}


int rawstor_close(RawstorVolume *volume) {
    int rval = close(volume->fd);
    if (rval == -1) {
        return -errno;
    }

    free(volume);

    return 0;
}


int rawstor_spec(int volume_id, struct RawstorVolumeSpec *spec) {
    char path[1024];

    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.spec", volume_id);
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
    RawstorVolume *volume,
    size_t offset,
    void *buf, size_t size,
    rawstor_cb cb, void *data)
{
    RawstorVolumeTransaction *t = rawstor_sb_acquire(
        volume->transactions_buffer);
    if (t == NULL) {
        return -errno;
    }
    t->volume = volume;
    t->cb = cb;
    t->data = data;

    return rawstor_fd_read(volume->fd, offset, buf, size, aio_cb, t);
}


int rawstor_readv(
    RawstorVolume *volume,
    size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_cb cb, void *data)
{
    RawstorVolumeTransaction *t = rawstor_sb_acquire(
        volume->transactions_buffer);
    if (t == NULL) {
        return -errno;
    }
    t->volume = volume;
    t->cb = cb;
    t->data = data;

    return rawstor_fd_readv(volume->fd, offset, iov, niov, aio_cb, t);
}


int rawstor_write(
    RawstorVolume *volume,
    size_t offset,
    void *buf, size_t size,
    rawstor_cb cb, void *data)
{
    RawstorVolumeTransaction *t = rawstor_sb_acquire(
        volume->transactions_buffer);
    if (t == NULL) {
        return -errno;
    }
    t->volume = volume;
    t->cb = cb;
    t->data = data;

    return rawstor_fd_write(volume->fd, offset, buf, size, aio_cb, t);
}


int rawstor_writev(
    RawstorVolume *volume,
    size_t offset,
    struct iovec *iov, unsigned int niov,
    rawstor_cb cb, void *data)
{
    RawstorVolumeTransaction *t = rawstor_sb_acquire(
        volume->transactions_buffer);
    if (t == NULL) {
        return -errno;
    }
    t->volume = volume;
    t->cb = cb;
    t->data = data;

    return rawstor_fd_writev(volume->fd, offset, iov, niov, aio_cb, t);
}
