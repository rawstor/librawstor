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

#include <unistd.h>

#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <system_error>


/**
 * TODO: Make it global
 */
#define QUEUE_DEPTH 256


namespace {


struct ObjectOp {
    RawstorCallback *callback;
    void *data;
};


class Object {
    private:
        struct RawstorUUID _id;
        struct RawstorMemPool *_ops_pool;
        RawstorConnection *_cn;

        static int _process(
            Object *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        Object(const struct RawstorUUID *object_id);

        ~Object();

        /**
         * TODO: Prevent class from copying.
         */

        void open(const struct RawstorSocketAddress *ost);

        void close();

        const struct RawstorUUID* id() const noexcept;

        int pread(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data) noexcept;

        int preadv(
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data) noexcept;

        int pwrite(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data) noexcept;

        int pwritev(
            struct iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data) noexcept;

};


Object::Object(const struct RawstorUUID *object_id) :
    _id(*object_id),
    _ops_pool(NULL),
    _cn(NULL)
{
    _ops_pool = rawstor_mempool_create(
        QUEUE_DEPTH, sizeof(struct ObjectOp));
    if (_ops_pool == NULL) {
        throw std::system_error(errno, std::generic_category(), __FILE__);
    }
}


Object::~Object() {
    if (_cn != NULL) {
        try {
            close();
        } catch (...) {
            /**
             * TODO: Handle errors on close.
             */
        }
    }
    rawstor_mempool_delete(_ops_pool);
}


int Object::_process(
    Object *object,
    size_t size, size_t res, int error, void *data) noexcept
{
    struct ObjectOp *op = (struct ObjectOp*)data;

    int ret = op->callback((RawstorObject*)object, size, res, error, op->data);

    rawstor_mempool_free(object->_ops_pool, op);

    return ret;
}


void Object::open(const struct RawstorSocketAddress *ost) {
    if (_cn != NULL) {
        throw std::runtime_error("Object already opened");
    }
    _cn = rawstor_connection_open((RawstorObject*)this, ost, 1, QUEUE_DEPTH);
    if (_cn == NULL) {
        throw std::system_error(errno, std::generic_category(), __FILE__);
    }
}


void Object::close() {
    if (_cn == NULL) {
        throw std::runtime_error("Object not opened");
    }
    int res = rawstor_connection_close(_cn);
    if (res) {
        throw std::system_error(errno, std::generic_category(), __FILE__);
    }
    _cn = NULL;
}


const struct RawstorUUID* Object::id() const noexcept {
    return &_id;
}


int Object::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data) noexcept
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    struct ObjectOp *op = (struct ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct ObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_pread(
        _cn, buf, size, offset,
        (RawstorCallback*)_process, op);
}


int Object::preadv(
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data) noexcept
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    struct ObjectOp *op = (struct ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct ObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_preadv(
        _cn, iov, niov, size, offset,
        (RawstorCallback*)_process, op);
}


int Object::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data) noexcept
{
    rawstor_debug(
        "%s(): offset = %jd, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, size);

    struct ObjectOp *op = (struct ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct ObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_pwrite(
        _cn, buf, size, offset,
        (RawstorCallback*)_process, op);
}


int Object::pwritev(
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data) noexcept
{
    rawstor_debug(
        "%s(): offset = %jd, niov = %u, size = %zu\n",
        __FUNCTION__, (intmax_t)offset, niov, size);

    struct ObjectOp *op =
        (struct ObjectOp*)rawstor_mempool_alloc(_ops_pool);
    if (op == NULL) {
        errno = ENOBUFS;
        return -errno;
    }

    *op = (struct ObjectOp) {
        .callback = cb,
        .data = data,
    };

    return rawstor_connection_pwritev(
        _cn, iov, niov, size, offset,
        (RawstorCallback*)_process, op);
}


} // unnamed namespace


struct RawstorObject {
    Object impl;
};


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
    try {
        Object *impl = new Object(object_id);
        impl->open(ost);

        *object = (RawstorObject*)impl;

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
    /**
     * TODO: Handle other errors.
     */
}


int rawstor_object_close(RawstorObject *object) {
    try {
        object->impl.close();

        delete &object->impl;

        return 0;
    } catch (const std::system_error &e) {
        return -e.code().value();
    }
    /**
     * TODO: Handle other errors.
     */
}


const struct RawstorUUID* rawstor_object_get_id(RawstorObject *object) {
    return object->impl.id();
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
    return object->impl.pread(buf, size, offset, cb, data);
}


int rawstor_object_preadv(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    return object->impl.preadv(iov, niov, size, offset, cb, data);
}


int rawstor_object_pwrite(
    RawstorObject *object,
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    return object->impl.pwrite(buf, size, offset, cb, data);
}


int rawstor_object_pwritev(
    RawstorObject *object,
    struct iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    return object->impl.pwritev(iov, niov, size, offset, cb, data);
}
