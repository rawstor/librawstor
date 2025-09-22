#ifndef RAWSTOR_SOCKET_OST_HPP
#define RAWSTOR_SOCKET_OST_HPP

#include "ost_protocol.h"

#include <rawstorstd/ringbuf.hpp>
#include <rawstorstd/socket_address.hpp>

#include <rawstorio/queue.h>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <cstddef>
#include <vector>

namespace rawstor {


struct SocketOp;

class Object;


class Socket {
    private:
        int _fd;
        Object *_object;

        std::vector<SocketOp*> _ops_array;
        RingBuf<SocketOp*> _ops;
        RawstorOSTFrameResponse _response;

        SocketOp* _acquire_op();
        void _release_op(SocketOp *op) noexcept;
        SocketOp* _find_op(unsigned int cid);

        int _connect(const SocketAddress &ost);

        void _writev_request(RawstorIOQueue *queue, SocketOp *op);
        void _read_response_set_object_id(RawstorIOQueue *queue, SocketOp *op);
        void _read_response_head(RawstorIOQueue *queue);
        void _read_response_body(RawstorIOQueue *queue, SocketOp *op);
        void _readv_response_body(RawstorIOQueue *queue, SocketOp *op);

        static void _next_read_response_body(
            RawstorIOQueue *queue, SocketOp *op);
        static void _next_readv_response_body(
            RawstorIOQueue *queue, SocketOp *op);

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
        static const char* engine_name() noexcept;

        Socket(const SocketAddress &ost, unsigned int depth);
        Socket(const Socket &) = delete;
        Socket(Socket &&other) noexcept;
        ~Socket();

        Socket& operator=(const Socket&) = delete;

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

#endif // RAWSTOR_SOCKET_OST_HPP
