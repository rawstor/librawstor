#include "object.h"

#include <rawstor.h>

#include "gcc.h"
#include "io.h"
#include "mempool.h"
#include "uuid.h"

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


typedef struct RawstorObjectOperation RawstorObjectOperation;

struct RawstorObjectOperation {
    RawstorObject *object;

    int (*dispatch)(RawstorObjectOperation *op);

    RawstorCallback *callback;

    void *data;
};


struct RawstorObject {
    int fd;
    RawstorMemPool *operations_pool;
};


const char *rawstor_object_backend_name = "file";


static int io_callback(RawstorIOEvent *event, void *data) {
    RawstorObjectOperation *op = data;
    int rval = op->callback(
        op->object,
        rawstor_io_event_size(event),
        rawstor_io_event_result(event),
        rawstor_io_event_error(event),
        op->data);
    rawstor_mempool_free(op->object->operations_pool, op);
    return rval;
}


int rawstor_object_create(
    const RawstorObjectSpec *spec, RawstorUUID *object_id)
{
    char spec_path[1024];
    int fd;
    RawstorUUID uuid;
    RawstorUUIDString uuid_string;
    while (1) {
        if (rawstor_uuid7_init(&uuid)) {
            return -errno;
        }
        rawstor_uuid_to_string(&uuid, &uuid_string);
        snprintf(
            spec_path, sizeof(spec_path),
            PREFIX "/rawstor-%s.spec", uuid_string);
        fd = open(spec_path, O_EXCL | O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
        if (fd != -1) {
            break;
        }
        if (errno != EEXIST) {
            return -errno;
        }
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
    snprintf(
        dat_path, sizeof(dat_path),
        PREFIX "/rawstor-%s.dat", uuid_string);
    fd = open(dat_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        int errsv = errno;
        unlink(spec_path);
        errno = errsv;
        return -errno;
    }
    rval = ftruncate(fd, spec->size);
    if (rval) {
        int errsv = errno;
        close(fd);
        unlink(dat_path);
        unlink(spec_path);
        errno = errsv;
        return -errno;
    }
    close(fd);

    *object_id = uuid;

    return 0;
}


int rawstor_object_delete(const RawstorUUID *object_id) {
    int rval;
    char path[1024];
    RawstorUUIDString uuid_string;

    rawstor_uuid_to_string(object_id, &uuid_string);

    snprintf(path, sizeof(path), PREFIX "/rawstor-%s.spec", uuid_string);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }

    snprintf(path, sizeof(path), PREFIX "/rawstor-%s.dat", uuid_string);
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }
    return 0;
}


int rawstor_object_open(
    const RawstorUUID *object_id, RawstorObject **object)
{
    RawstorUUIDString uuid_string;

    rawstor_uuid_to_string(object_id, &uuid_string);

    RawstorObject *ret = malloc(sizeof(RawstorObject));
    if (ret == NULL) {
        return -errno;
    }

    ret->operations_pool = rawstor_mempool_create(
        QUEUE_DEPTH,
        sizeof(RawstorObjectOperation));
    if (ret->operations_pool == NULL) {
        free(ret);
        return -errno;
    }

    char path[1024];
    snprintf(path, sizeof(path), PREFIX "/rawstor-%s.dat", uuid_string);
    ret->fd = open(path, O_RDWR | O_NONBLOCK);
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


int rawstor_object_spec(const RawstorUUID *object_id, RawstorObjectSpec *spec) {
    char path[1024];
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);

    snprintf(path, sizeof(path), PREFIX "/rawstor-%s.spec", uuid_string);
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


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_pread(
        object->fd, buf, size, offset,
        io_callback, op);
}


int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_preadv(
        object->fd, iov, niov, size, offset,
        io_callback, op);
}


int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_pwrite(
        object->fd, buf, size, offset,
        io_callback, op);
}


int rawstor_object_pwritev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    if (rawstor_mempool_available(object->operations_pool) == 0) {
        errno = ENOBUFS;
        return -errno;
    }
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    *op = (RawstorObjectOperation) {
        .object = object,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_pwritev(
        object->fd, iov, niov, size, offset,
        io_callback, op);
}
