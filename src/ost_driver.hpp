#ifndef RAWSTOR_OST_DRIVER_HPP
#define RAWSTOR_OST_DRIVER_HPP

#include "driver.hpp"
#include "ost_protocol.h"

#include <rawstorstd/ringbuf.hpp>
#include <rawstorstd/uri.hpp>

#include <rawstorio/queue.hpp>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <string>
#include <unordered_map>

#include <cstddef>

namespace rawstor {
namespace ost {


class DriverOp;
class DriverOpResponse;


class Driver final: public rawstor::Driver {
    private:
        RawstorObject *_object;
        std::unordered_map<uint16_t, DriverOp*> _ops;
        DriverOpResponse *_op_response;

        DriverOp* _find_op(uint16_t cid);

        int _connect();
        void _read_response_head(rawstor::io::Queue &queue);
        static int _read_response_head_cb(
            RawstorIOEvent *event, void *data) noexcept;

    public:
        Driver(const URI &uri, unsigned int depth);
        ~Driver();

        void register_request(DriverOp &op);
        void unregister_request(DriverOp &op);

        inline RawstorObject* object() noexcept {
            return _object;
        }

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
            RawstorObject *object,
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


}} // rawstor::ost

#endif // RAWSTOR_OST_DRIVER_HPP
