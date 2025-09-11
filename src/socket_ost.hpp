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

        int _response_loop;
        std::vector<SocketOp*> _ops_array;
        RawstorRingBuf *_ops;
        RawstorOSTFrameResponse _response_frame;

        int _connect(const RawstorSocketAddress &ost);

        void _set_object_id(int fd, const RawstorUUID &id);

        void _response_head_read();

        static int _op_process_read(SocketOp *op, int fd) noexcept;

        static int _op_process_readv(SocketOp *op, int fd) noexcept;

        static int _op_process_write(SocketOp *op, int fd) noexcept;

        static int _read_request_sent(
            RawstorIOEvent *event, void *data) noexcept;

        static int _write_requestv_sent(
            RawstorIOEvent *event, void *data) noexcept;

        static int _response_body_received(
            RawstorIOEvent *event, void *data) noexcept;

        static int _responsev_body_received(
            RawstorIOEvent *event, void *data) noexcept;

        static int _response_head_received(
            RawstorIOEvent *event, void *data) noexcept;

    public:
        Socket(const RawstorSocketAddress &ost, unsigned int depth);
        Socket(const Socket &) = delete;
        Socket(Socket &&other);
        ~Socket();

        Socket& operator=(const Socket&) = delete;

        void create(const RawstorObjectSpec &sp, RawstorUUID *id);

        void remove(rawstor::Object *object);

        void spec(rawstor::Object *object, RawstorObjectSpec *sp);

        void open(rawstor::Object *object);

        void close();

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
