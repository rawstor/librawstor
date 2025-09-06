#include <rawstor/object.h>
#include "object_internals.h"

#include "connection_ost.h"
#include "rawstor_internals.h"

#include <rawstorstd/gcc.h>
#include <rawstorstd/logging.h>
#include <rawstorstd/mempool.h>
#include <rawstorstd/uuid.h>

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


struct RawstorObjectOp {
    RawstorCallback *callback;
    void *data;
};


struct RawstorObject {
    struct RawstorUUID id;

    RawstorConnection *cn;

    struct RawstorMemPool *ops_pool;
};


static int object_op_process(
    RawstorObject *object, size_t size, size_t res, int error, void *data)
{
    struct RawstorObjectOp *op = (struct RawstorObjectOp*)data;

    int ret = op->callback(object, size, res, error, op->data);

    rawstor_mempool_free(object->ops_pool, op);

    return ret;
}


const char* rawstor_object_backend_name(void) {
    return "ost";
};


int rawstor_object_create(
    const struct RawstorObjectSpec *spec,
    struct RawstorUUID *object_id)
{
    return rawstor_object_create_ost(rawstor_default_ost(), spec, object_id);
}


int rawstor_object_create_ost(
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const struct RawstorObjectSpec RAWSTOR_UNUSED *spec,
    struct RawstorUUID *object_id)
{
    /**
     * TODO: Implement me.
     */
    rawstor_uuid7_init(object_id);

    return 0;
}


int rawstor_object_delete(const struct RawstorUUID *object_id) {
    return rawstor_object_delete_ost(rawstor_default_ost(), object_id);
}


int rawstor_object_delete_ost(
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const struct RawstorUUID RAWSTOR_UNUSED *object_id)
{
    fprintf(stderr, "rawstor_object_delete() not implemented\n");
    exit(1);

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
    RawstorObject *obj = malloc(sizeof(RawstorObject));
    if (obj == NULL) {
        goto err_obj;
    }

    obj->id = *object_id;

    obj->ops_pool = rawstor_mempool_create(
        QUEUE_DEPTH, sizeof(struct RawstorObjectOp));
    if (obj->ops_pool == NULL) {
        goto err_ops_pool;
    }

    obj->cn = rawstor_connection_open(obj, ost, 1, QUEUE_DEPTH);
    if (obj->cn == NULL) {
        goto err_cn;
    }

    *object = obj;

    return 0;

err_cn:
    rawstor_mempool_delete(obj->ops_pool);
err_ops_pool:
    free(obj);
err_obj:
    return -errno;
}


int rawstor_object_close(RawstorObject *object) {
    int res = rawstor_connection_close(object->cn);
    if (res) {
        return res;
    }

    rawstor_mempool_delete(object->ops_pool);

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
    const struct RawstorSocketAddress RAWSTOR_UNUSED *ost,
    const struct RawstorUUID RAWSTOR_UNUSED *object_id,
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


int rawstor_object_pread(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    struct RawstorObjectOp *op = rawstor_mempool_alloc(object->ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct RawstorObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_pread(
        object->cn, buf, size, offset,
        object_op_process, op);
}


int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    struct RawstorObjectOp *op = rawstor_mempool_alloc(object->ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct RawstorObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_preadv(
        object->cn, iov, niov, size, offset,
        object_op_process, op);
}


int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    struct RawstorObjectOp *op = rawstor_mempool_alloc(object->ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct RawstorObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_pwrite(
        object->cn, buf, size, offset,
        object_op_process, op);
}


int rawstor_object_pwritev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    struct RawstorObjectOp *op = rawstor_mempool_alloc(object->ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct RawstorObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_pwritev(
        object->cn, iov, niov, size, offset,
        object_op_process, op);
}
