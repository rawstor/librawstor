#ifndef RAWSTOR_SOCKET_OST_HPP
#define RAWSTOR_SOCKET_OST_HPP

#include "ost_protocol.h"

#include <rawstorstd/ringbuf.h>

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
        RawstorRingBuf *_ops;
        RawstorOSTFrameResponse _response;

        int _connect(const RawstorSocketAddress &ost);

        void _set_object_id(int fd, const RawstorUUID &id);

        void _writev_request(SocketOp *op);
        void _read_response_head();
        void _read_response_body(SocketOp *op);
        void _readv_response_body(SocketOp *op);

        static int _writev_request_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _read_response_head_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _read_response_body_cb(
            RawstorIOEvent *event, void *data) noexcept;
        static int _readv_response_body_cb(
            RawstorIOEvent *event, void *data) noexcept;

        static int _op_process_read(SocketOp *op) noexcept;
        static int _op_process_readv(SocketOp *op) noexcept;
        static int _op_process_write(SocketOp *op) noexcept;

    public:
        Socket(const RawstorSocketAddress &ost, unsigned int depth);
        Socket(const Socket &) = delete;
        Socket(Socket &&other) noexcept;
        ~Socket();

        Socket& operator=(const Socket&) = delete;

        void create(const RawstorObjectSpec &sp, RawstorUUID *id);

        void remove(const RawstorUUID &id);

        void spec(const RawstorUUID &id, RawstorObjectSpec *sp);

        void set_object(rawstor::Object *object);

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
