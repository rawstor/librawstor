#ifndef RAWSTOR_FILE_DRIVER_HPP
#define RAWSTOR_FILE_DRIVER_HPP

#include "driver.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/mempool.hpp>
#include <rawstorstd/socket_address.hpp>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <string>

namespace rawstor {
namespace file {


struct DriverOp;


class Driver: public rawstor::Driver {
    private:
        Object *_object;
        MemPool<DriverOp> _ops_pool;

        DriverOp* _acquire_op();
        void _release_op(DriverOp *op) noexcept;

        int _connect(const RawstorUUID &id);

        static int _io_cb(RawstorIOEvent *event, void *data) noexcept;

    public:
        Driver(const SocketAddress &ost, unsigned int depth);

        void create(
            rawstor::io::Queue &queue,
            const RawstorObjectSpec &sp, RawstorUUID *id,
            RawstorCallback *cb, void *data);

        void remove(
            rawstor::io::Queue &queue,
            const RawstorUUID &id,
            RawstorCallback *cb, void *data);

        void spec(
            rawstor::io::Queue &queue,
            const RawstorUUID &id, RawstorObjectSpec *sp,
            RawstorCallback *cb, void *data);

        void set_object(
            rawstor::io::Queue &queue,
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


}} // rawstor::file


#endif // RAWSTOR_FILE_DRIVER_HPP
