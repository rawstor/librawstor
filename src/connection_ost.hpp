#ifndef RAWSTOR_CONNECTION_OST_HPP
#define RAWSTOR_CONNECTION_OST_HPP

#include "ost_protocol.h"

#include <rawstorstd/ringbuf.h>

#include <rawstor/io_event.h>
#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <cstddef>
#include <vector>

namespace rawstor {


struct ConnectionOp;


class Object;


class Connection {
    private:
        rawstor::Object *_object;

        std::vector<int> _fds;
        size_t _ifds;

        unsigned int _depth;

        int _response_loop;
        std::vector<ConnectionOp*> _ops_array;
        RawstorRingBuf *_ops;
        RawstorOSTFrameResponse _response_frame;

        int _get_next_fd();

        int _connect(const RawstorSocketAddress &ost);

        void _set_object_id(int fd);

        void _response_head_read();

        static int _op_process_read(ConnectionOp *op, int fd) noexcept;

        static int _op_process_readv(ConnectionOp *op, int fd) noexcept;

        static int _op_process_write(ConnectionOp *op, int fd) noexcept;

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
        Connection(rawstor::Object *object, unsigned int depth);
        Connection(const Connection &) = delete;
        ~Connection();

        Connection& operator=(const Connection&) = delete;

        void create(
            const RawstorSocketAddress &ost,
            const RawstorObjectSpec &sp,
            RawstorUUID *id);

        void remove(const RawstorSocketAddress &ost);

        void spec(const RawstorSocketAddress &ost, RawstorObjectSpec *sp);

        void open(const RawstorSocketAddress &ost, size_t count);

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

#endif // RAWSTOR_CONNECTION_OST_HPP
