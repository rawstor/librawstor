#include <rawstor/object.h>
#include "object_internals.h"

#include "opts.h"
#include "rawstor_internals.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.h>

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>

#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


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
    struct RawstorUUID id;
    int fd;
    RawstorMemPool *operations_pool;
};


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


static int get_ost_path(
    const char *ost_host, unsigned int ost_port,
    char *buffer, size_t size)
{
    static const char prefix[] = ".";

    int res = snprintf(
        buffer, size,
        "%s/ost-%s:%u", prefix, ost_host, ost_port);
    if (res < 0) {
        return -errno;
    }

    return 0;
}


static int get_object_spec_path(
    const char *ost_path, const char *uuid,
    char *buffer, size_t size)
{
    int res = snprintf(
        buffer, size,
        "%s/rawstor-%s.spec", ost_path, uuid);
    if (res < 0) {
        return -errno;
    }

    return 0;
}


static int get_object_dat_path(
    const char *ost_path, const char *uuid,
    char *buffer, size_t size)
{
    int res = snprintf(
        buffer, size,
        "%s/rawstor-%s.dat", ost_path, uuid);
    if (res < 0) {
        return -errno;
    }

    return 0;
}


static int object_write_dat(
    const char *ost_path,
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id)
{
    int errsv;
    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);

    char dat_path[PATH_MAX];
    if (get_object_dat_path(
        ost_path, uuid_string, dat_path, sizeof(dat_path)))
    {
        goto err_object_dat_path;
    }
    int fd = open(dat_path, O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        goto err_open;
    }
    int res = ftruncate(fd, spec->size);
    if (res) {
        goto err_ftruncate;
    }
    close(fd);

    return 0;

err_ftruncate:
    errsv = errno;
    close(fd);
    unlink(dat_path);
    errno = errsv;
err_open:
err_object_dat_path:
    return -errno;
}


const char* rawstor_object_backend_name() {
    return "file";
}


int rawstor_object_create(
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id)
{
    return rawstor_object_create_ost(rawstor_default_ost(), spec, object_id);
}


int rawstor_object_create_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id)
{
    int errsv;
    char ost_path[PATH_MAX];
    if (get_ost_path(ost->host, ost->port, ost_path, sizeof(ost_path))) {
        return -errno;
    }
    if (mkdir(ost_path, 0755)) {
        if (errno != EEXIST) {
            return -errno;
        }
    }

    struct RawstorUUID uuid;
    RawstorUUIDString uuid_string;
    char spec_path[PATH_MAX];
    int fd;
    while (1) {
        if (rawstor_uuid7_init(&uuid)) {
            return -errno;
        }
        rawstor_uuid_to_string(&uuid, &uuid_string);
        if (get_object_spec_path(
            ost_path, uuid_string, spec_path, sizeof(spec_path)))
        {
            return -errno;
        }
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
        goto err_write;
    }

    if (object_write_dat(ost_path, spec, &uuid)) {
        goto err_write_dat;
    }

    close(fd);

    *object_id = uuid;

    return 0;

err_write_dat:
    errsv = errno;
    unlink(spec_path);
    errno = errsv;
err_write:
    errsv = errno;
    close(fd);
    errno = errsv;
    return -errno;
}


int rawstor_object_delete(const struct RawstorUUID *object_id) {
    return rawstor_object_delete_ost(rawstor_default_ost(), object_id);
}


int rawstor_object_delete_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id)
{
    char ost_path[PATH_MAX];
    if (get_ost_path(ost->host, ost->port, ost_path, sizeof(ost_path))) {
        return -errno;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);

    int rval;
    char path[PATH_MAX];
    if (get_object_spec_path(ost_path, uuid_string, path, sizeof(path))) {
        return -errno;
    }
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }

    if (get_object_dat_path(ost_path, uuid_string, path, sizeof(path))) {
        return -errno;
    }
    rval = unlink(path);
    if (rval == -1) {
        return -errno;
    }
    return 0;
}


int rawstor_object_open(
    const struct RawstorUUID *object_id,
    RawstorObject **object)
{
    return rawstor_object_open_ost(rawstor_default_ost(), object_id, object);
}


int rawstor_object_open_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    RawstorObject **object)
{
    char ost_path[PATH_MAX];
    if (get_ost_path(ost->host, ost->port, ost_path, sizeof(ost_path))) {
        goto err_ost_path;
    }

    RawstorObject *obj = malloc(sizeof(RawstorObject));
    if (obj == NULL) {
        goto err_object;
    }

    obj->id = *object_id;

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(&obj->id, &uuid_string);

    obj->operations_pool = rawstor_mempool_create(
        QUEUE_DEPTH,
        sizeof(RawstorObjectOperation));
    if (obj->operations_pool == NULL) {
        goto err_operations_pool;
    }

    char path[PATH_MAX];
    if (get_object_dat_path(ost_path, uuid_string, path, sizeof(path))) {
        goto err_dat_path;
    }
    obj->fd = open(path, O_RDWR | O_NONBLOCK);
    if (obj->fd == -1) {
        goto err_open;
    }

    *object = obj;

    return 0;

err_open:
err_dat_path:
    rawstor_mempool_delete(obj->operations_pool);
err_operations_pool:
    free(obj);
err_object:
err_ost_path:
    return -errno;
}


int rawstor_object_close(RawstorObject *object) {
    int rval = close(object->fd);
    if (rval == -1) {
        return -errno;
    }

    free(object);

    return 0;
}


const struct RawstorUUID* rawstor_object_get_id(RawstorObject *object) {
    return &object->id;
}


int rawstor_object_spec(
    const struct RawstorUUID *object_id,
    struct RawstorObjectSpec *spec)
{
    return rawstor_object_spec_ost(rawstor_default_ost(), object_id, spec);
}


int rawstor_object_spec_ost(
    const struct RawstorSocketAddress *ost,
    const struct RawstorUUID *object_id,
    struct RawstorObjectSpec *spec)
{
    int errsv;
    char ost_path[PATH_MAX];
    if (get_ost_path(ost->host, ost->port, ost_path, sizeof(ost_path))) {
        goto err_ost_path;
    }

    RawstorUUIDString uuid_string;
    rawstor_uuid_to_string(object_id, &uuid_string);

    char path[PATH_MAX];
    if (get_object_spec_path(ost_path, uuid_string, path, sizeof(path))) {
        goto err_spec_path;
    }
    int fd = open(path, O_RDONLY);
    if (fd == -1) {
        goto err_open;
    }
    ssize_t rval = read(fd, spec, sizeof(*spec));
    if (rval == -1) {
        goto err_read;
    }
    close(fd);
    return 0;

err_read:
    errsv = errno;
    close(fd);
    errno = errsv;
    return -errno;
err_open:
err_spec_path:
err_ost_path:
    return -errno;
}


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    if (op == NULL) {
        return -errno;
    }

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
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    if (op == NULL) {
        return -errno;
    }

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
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    if (op == NULL) {
        return -errno;
    }

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
    RawstorObjectOperation *op = rawstor_mempool_alloc(object->operations_pool);
    if (op == NULL) {
        return -errno;
    }

    *op = (RawstorObjectOperation) {
        .object = object,
        .callback = cb,
        .data = data,
    };

    return rawstor_fd_pwritev(
        object->fd, iov, niov, size, offset,
        io_callback, op);
}
