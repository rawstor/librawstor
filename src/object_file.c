#include <rawstor.h>

#include "aio.h"
#include "pool.h"

#include <sys/types.h>
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


typedef struct RawstorObjectTransaction {
    RawstorObject *object;
    union {
        rawstor_scalar_cb scalar_cb;
        rawstor_vector_cb vector_cb;
    } cb;
    void *data;
} RawstorObjectTransaction;


struct RawstorObject {
    int fd;
    RawstorPool *transactions_pool;
};


static int aio_scalar_cb(
    int, off_t offset, ssize_t res,
    void *buf, size_t size,
    void *data)
{
    RawstorObjectTransaction *t = data;
    int rval = t->cb.scalar_cb(
        t->object, offset, res,
        buf, size,
        t->data);
    rawstor_pool_free(t->object->transactions_pool, t);
    return rval;
}


static int aio_vector_cb(
    int, off_t offset, ssize_t res,
    struct iovec *iov, unsigned int niov, size_t size,
    void *data)
{
    RawstorObjectTransaction *t = data;
    int rval = t->cb.vector_cb(
        t->object, offset, res,
        iov, niov, size,
        t->data);
    rawstor_pool_free(t->object->transactions_pool, t);
    return rval;
}


int rawstor_object_create(struct RawstorObjectSpec spec, int *object_id) {
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

    *object_id = id;

    return 0;
}


int rawstor_object_delete(int object_id) {
    int rval;
    char path[1024];

    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.spec", object_id);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }

    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.dat", object_id);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }
    return 0;
}


int rawstor_object_open(int object_id, RawstorObject **object) {
    RawstorObject *ret = malloc(sizeof(RawstorObject));
    if (ret == NULL) {
        return -errno;
    }

    ret->transactions_pool = rawstor_pool_create(
        QUEUE_DEPTH,
        sizeof(RawstorObjectTransaction));
    if (ret->transactions_pool == NULL) {
        free(ret);
        return -errno;
    }

    char path[1024];
    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.dat", object_id);
    ret->fd = open(path, O_RDWR);
    if (ret->fd == -1) {
        int errsv = errno;
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


int rawstor_object_spec(int object_id, struct RawstorObjectSpec *spec) {
    char path[1024];

    snprintf(path, sizeof(path), PREFIX "/rawstor-%d.spec", object_id);
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


int rawstor_object_read(
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_scalar_cb cb, void *data)
{
    if (rawstor_pool_count(object->transactions_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectTransaction *t = rawstor_pool_alloc(object->transactions_pool);
    t->object = object;
    t->cb.scalar_cb = cb;
    t->data = data;

    return rawstor_fd_read(
        object->fd, offset,
        buf, size,
        aio_scalar_cb, t);
}


int rawstor_object_readv(
    RawstorObject *object,
    off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_cb cb, void *data)
{
    if (rawstor_pool_count(object->transactions_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectTransaction *t = rawstor_pool_alloc(object->transactions_pool);
    t->object = object;
    t->cb.vector_cb = cb;
    t->data = data;

    return rawstor_fd_readv(
        object->fd, offset,
        iov, niov, size,
        aio_vector_cb, t);
}


int rawstor_object_write(
    RawstorObject *object,
    off_t offset,
    void *buf, size_t size,
    rawstor_scalar_cb cb, void *data)
{
    if (rawstor_pool_count(object->transactions_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectTransaction *t = rawstor_pool_alloc(object->transactions_pool);
    t->object = object;
    t->cb.scalar_cb = cb;
    t->data = data;

    return rawstor_fd_write(
        object->fd, offset,
        buf, size,
        aio_scalar_cb, t);
}


int rawstor_object_writev(
    RawstorObject *object,
    off_t offset,
    struct iovec *iov, unsigned int niov, size_t size,
    rawstor_vector_cb cb, void *data)
{
    if (rawstor_pool_count(object->transactions_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectTransaction *t = rawstor_pool_alloc(object->transactions_pool);
    t->object = object;
    t->cb.vector_cb = cb;
    t->data = data;

    return rawstor_fd_writev(
        object->fd, offset,
        iov, niov, size,
        aio_vector_cb, t);
}
