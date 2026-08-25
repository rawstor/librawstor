#include "object.hpp"
#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/target.h>

#include <rawstd/logging.h>
#include <rawstd/uri.hpp>

#include <memory>
#include <new>
#include <string>
#include <system_error>

#include <cerrno>

// Backport shim: the pre-target/location-rework public C ABI
// (rawstor_object_spec()/_list()/_create()/_create_at()/_remove()/_open()/
// _close()/_id()/_location()/_pread()/_preadv()/_pwrite()/_pwritev()/
// _flush(), see <rawstor/object.h>) implemented as blocking wrappers
// (spec/list/create/create_at/remove/open/close -- each spins up or reuses
// a queue and pumps rawio_wait() to completion, same idiom as
// cli/rawio_sync.c) or thin per-call trampolines (id/location -- purely
// syntactic, no I/O; pread/preadv/pwrite/pwritev/flush -- see below) over
// the target/location/object2 functions that now do the real work.
// Deleted, along with the old declarations in <rawstor/object.h>, once the
// public API itself drops the old names.

namespace {

// Shared by spec/list/create/create_at/remove -- all five report their
// result via an `int (*)(ssize_t result, void* data)` callback.
struct SyncOp {
    RawIOQueue* queue;
    ssize_t result;
    bool done;
};

int sync_op_init(SyncOp* op) {
    op->result = 0;
    op->done = false;
    return rawio_queue_create(2, &op->queue);
}

void sync_op_destroy(SyncOp* op) {
    rawio_queue_delete(op->queue);
}

int sync_op_cb(ssize_t result, void* data) {
    auto* op = static_cast<SyncOp*>(data);
    op->result = result;
    op->done = true;
    return 0;
}

ssize_t sync_op_wait(SyncOp* op) {
    while (!op->done) {
        int wres = rawio_wait(op->queue);
        if (wres < 0) {
            return wres;
        }
    }
    return op->result;
}

// Shared by open/close -- both report completion via the same ssize_t
// result callback shape SyncOp's group uses (negative -> -errno, zero ->
// success), but (unlike SyncOp's group) pump a caller/object-owned queue
// rather than a private one.
struct ErrOp {
    bool done;
    int error;
};

int err_op_cb(ssize_t result, void* data) {
    auto* op = static_cast<ErrOp*>(data);
    op->error = result < 0 ? static_cast<int>(-result) : 0;
    op->done = true;
    return 0;
}

int err_op_wait(RawIOQueue* queue, ErrOp* op) {
    while (!op->done) {
        int wres = rawio_wait(queue);
        if (wres < 0) {
            return wres;
        }
    }
    return op->error ? -op->error : 0;
}

} // namespace

int rawstor_object_spec(
    const char* target, struct RawstorObjectSpec* spec
) noexcept {
    try {
        SyncOp op;
        int res = sync_op_init(&op);
        if (res < 0) {
            return res;
        }
        res = rawstor_target_spec(op.queue, target, spec, sync_op_cb, &op);
        if (res >= 0) {
            res = static_cast<int>(sync_op_wait(&op));
        }
        sync_op_destroy(&op);
        return res;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_list(
    const char* location, unsigned int limit, RawstorStringList** targets,
    RawstorPaginationToken* token
) noexcept {
    try {
        SyncOp op;
        int res = sync_op_init(&op);
        if (res < 0) {
            return res;
        }
        res = rawstor_location_list(
            op.queue, location, limit, targets, token, sync_op_cb, &op
        );
        if (res >= 0) {
            res = static_cast<int>(sync_op_wait(&op));
        }
        sync_op_destroy(&op);
        return res;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_create(
    const char* target, const struct RawstorObjectSpec* spec
) noexcept {
    try {
        SyncOp op;
        int res = sync_op_init(&op);
        if (res < 0) {
            return res;
        }
        res = rawstor_target_create(op.queue, target, spec, sync_op_cb, &op);
        if (res >= 0) {
            res = static_cast<int>(sync_op_wait(&op));
        }
        sync_op_destroy(&op);
        return res;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_create_at(
    const char* location, const char* uuid,
    const struct RawstorObjectSpec* spec, char* target, size_t size
) noexcept {
    try {
        SyncOp op;
        int res = sync_op_init(&op);
        if (res < 0) {
            return res;
        }
        res = rawstor_location_create(
            op.queue, location, uuid, spec, target, size, sync_op_cb, &op
        );
        if (res >= 0) {
            res = static_cast<int>(sync_op_wait(&op));
        }
        sync_op_destroy(&op);
        return res;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_remove(const char* target) noexcept {
    try {
        SyncOp op;
        int res = sync_op_init(&op);
        if (res < 0) {
            return res;
        }
        res = rawstor_target_remove(op.queue, target, sync_op_cb, &op);
        if (res >= 0) {
            res = static_cast<int>(sync_op_wait(&op));
        }
        sync_op_destroy(&op);
        return res;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_open(
    RawIOQueue* queue, const char* target, RawstorObject** object
) noexcept {
    try {
        ErrOp op{false, 0};
        int res = rawstor_target_open(queue, target, object, err_op_cb, &op);
        if (res < 0) {
            return res;
        }
        return err_op_wait(queue, &op);
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_close(RawstorObject* object) noexcept {
    try {
        // rawstor_object_close2() has no queue parameter of its own -- it
        // drives completion on the same queue the object was opened on
        // (Object::_queue) -- so that's what this pumps too.
        rawio::Queue& queue = static_cast<rawstor::Object*>(object)->queue();
        ErrOp op{false, 0};
        int res = rawstor_object_close2(object, err_op_cb, &op);
        if (res < 0) {
            return res;
        }
        return err_op_wait(&queue, &op);
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_id(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        const auto* o = static_cast<const rawstor::Object*>(object);
        std::string target = rawstd::URI::uris(o->target().uris());
        return rawstor_target_id(target.c_str(), buf, size);
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

int rawstor_object_location(
    const RawstorObject* object, char* buf, size_t size
) noexcept {
    try {
        const auto* o = static_cast<const rawstor::Object*>(object);
        std::string target = rawstd::URI::uris(o->target().uris());
        return rawstor_target_location(target.c_str(), buf, size);
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    } catch (const std::exception& e) {
        rawstd_error("%s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

namespace {

// Shared by pread/preadv/pwrite/pwritev below (flush uses its own
// legacy_flush_cb() further down, since rawstor_object_flush2()'s own
// callback shape differs from the rest of this group's) -- see
// include/rawstor/object.h's RawstorCallback deprecation note.
struct LegacyIoCtx {
    RawstorObject* object;
    size_t size;
    RawstorCallback* cb;
    void* data;
};

int legacy_io_cb(size_t result, int error, void* data) {
    std::unique_ptr<LegacyIoCtx> ctx(static_cast<LegacyIoCtx*>(data));
    return ctx->cb(ctx->object, ctx->size, result, error, ctx->data);
}

// rawstor_object_flush2()'s own callback shape (ssize_t result: negative
// -> -errno, zero -> success) folded back into the old RawstorCallback
// shape (object/size/result/error/data) -- flush always reports
// size = result = 0.
int legacy_flush_cb(ssize_t result, void* data) {
    std::unique_ptr<LegacyIoCtx> ctx(static_cast<LegacyIoCtx*>(data));
    int error = result < 0 ? static_cast<int>(-result) : 0;
    return ctx->cb(ctx->object, 0, 0, error, ctx->data);
}

} // namespace

int rawstor_object_pread(
    RawstorObject* object, void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) noexcept {
    try {
        auto ctx =
            std::make_unique<LegacyIoCtx>(LegacyIoCtx{object, size, cb, data});
        int res = rawstor_object_pread2(
            object, buf, size, offset, legacy_io_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_preadv(
    RawstorObject* object, iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        auto ctx =
            std::make_unique<LegacyIoCtx>(LegacyIoCtx{object, size, cb, data});
        int res = rawstor_object_preadv2(
            object, iov, niov, size, offset, legacy_io_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_pwrite(
    RawstorObject* object, const void* buf, size_t size, off_t offset,
    RawstorCallback* cb, void* data
) noexcept {
    try {
        auto ctx =
            std::make_unique<LegacyIoCtx>(LegacyIoCtx{object, size, cb, data});
        // sync stays hardcoded, matching this branch's pre-existing
        // rawstor_object_pwrite() (which never had a sync argument of its
        // own -- that C API surface hasn't been backported here).
        int res = rawstor_object_pwrite2(
            object, buf, size, offset, /*sync=*/false, legacy_io_cb, ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_pwritev(
    RawstorObject* object, const iovec* iov, unsigned int niov, size_t size,
    off_t offset, RawstorCallback* cb, void* data
) noexcept {
    try {
        auto ctx =
            std::make_unique<LegacyIoCtx>(LegacyIoCtx{object, size, cb, data});
        // sync stays hardcoded, matching this branch's pre-existing
        // rawstor_object_pwritev() (which never had a sync argument of its
        // own -- that C API surface hasn't been backported here).
        int res = rawstor_object_pwritev2(
            object, iov, niov, size, offset, /*sync=*/false, legacy_io_cb,
            ctx.get()
        );
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}

int rawstor_object_flush(
    RawstorObject* object, RawstorCallback* cb, void* data
) noexcept {
    try {
        auto ctx =
            std::make_unique<LegacyIoCtx>(LegacyIoCtx{object, 0, cb, data});
        int res = rawstor_object_flush2(object, legacy_flush_cb, ctx.get());
        if (res < 0) {
            return res;
        }
        ctx.release();
        return 0;
    } catch (const std::bad_alloc&) {
        return -ENOMEM;
    }
}
