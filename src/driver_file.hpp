#ifndef RAWSTOR_DRIVER_FILE_HPP
#define RAWSTOR_DRIVER_FILE_HPP

#include "driver.hpp"

#include <rawstorstd/mempool.hpp>
#include <rawstorstd/socket_address.hpp>

#include <rawstorio/queue.h>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <string>

namespace rawstor {


struct DriverOp;

class Object;


class DriverFile: public Driver {
    private:
        Object *_object;
        MemPool<DriverOp> _ops_pool;

        DriverOp* _acquire_op();
        void _release_op(DriverOp *op) noexcept;

        int _connect(const RawstorUUID &id);

        static int _io_cb(RawstorIOEvent *event, void *data) noexcept;

    public:
        DriverFile(const SocketAddress &ost, unsigned int depth);
        DriverFile(DriverFile &&other) noexcept;

        void create(
            RawstorIOQueue *queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            RawstorCallback *cb, void *data);

        void remove(
            RawstorIOQueue *queue,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data);

        void spec(
            RawstorIOQueue *queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            RawstorCallback *cb, void *data);

        void set_object(
            RawstorIOQueue *queue,
            rawstor::Object *object,
            RawstorCallback *cb, void *data);

        void pread(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void preadv(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void pwrite(
            void *buf, size_t size, off_t offset,
            RawstorCallback *cb, void *data);

        void pwritev(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data);
};


} // rawstor


#endif // RAWSTOR_DRIVER_FILE_HPP
