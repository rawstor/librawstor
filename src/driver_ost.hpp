#ifndef RAWSTOR_DRIVER_OST_HPP
#define RAWSTOR_DRIVER_OST_HPP

#include "driver.hpp"
#include "ost_protocol.h"

#include <rawstorstd/ringbuf.hpp>
#include <rawstorstd/socket_address.hpp>

#include <rawstorio/queue.hpp>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <string>
#include <vector>

#include <cstddef>

namespace rawstor {


struct DriverOp;

class Object;


class DriverOST: public Driver {
    private:
        Object *_object;

        std::vector<DriverOp*> _ops_array;
        RingBuf<DriverOp*> _ops;
        RawstorOSTFrameResponse _response;

        void _validate_event(RawstorIOEvent *event);
        void _validate_response(const RawstorOSTFrameResponse &response);
        void _validate_cmd(
            enum RawstorOSTCommandType cmd,
            enum RawstorOSTCommandType expected);
        void _validate_hash(uint64_t hash, uint64_t expected);

        DriverOp* _acquire_op();
        void _release_op(DriverOp *op) noexcept;
        DriverOp* _find_op(unsigned int cid);

        int _connect();

        void _writev_request(rawstor::io::Queue &queue, DriverOp *op);
        void _read_response_set_object_id(
            rawstor::io::Queue &queue, DriverOp *op);
        void _read_response_head(rawstor::io::Queue &queue);
        void _read_response_body(rawstor::io::Queue &queue, DriverOp *op);
        void _readv_response_body(rawstor::io::Queue &queue, DriverOp *op);

        static void _next_read_response_body(
            rawstor::io::Queue &queue, DriverOp *op);
        static void _next_readv_response_body(
            rawstor::io::Queue &queue, DriverOp *op);

        static int _writev_request_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _read_response_set_object_id_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _read_response_head_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _read_response_body_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _readv_response_body_cb(
            RawstorIOEvent *event, void *data) noexcept;

    public:
        DriverOST(const SocketAddress &ost, unsigned int depth);
        DriverOST(DriverOST &&other) noexcept;
        ~DriverOST();

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


} // rawstor

#endif // RAWSTOR_DRIVER_OST_HPP
