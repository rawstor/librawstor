#include "connection.hpp"

#include "opts.h"
#include "socket.hpp"

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor/object.h>

#include <memory>
#include <stdexcept>

#include <cerrno>

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256


#define op_trace(cid, event) \
    rawstor_debug( \
        "[%u] %s(): %zi of %zu\n", \
        cid, __FUNCTION__, \
        rawstor_io_event_result(event), \
        rawstor_io_event_size(event))


namespace {


class Queue {
    private:
        int _operations;
        RawstorIOQueue *_impl;

    public:
        static int callback(
            RawstorObject *,
            size_t size, size_t res, int error, void *data) noexcept;

        Queue(int operations, unsigned int depth);
        Queue(const Queue &) = delete;
        ~Queue();

        Queue& operator=(const Queue &) = delete;

        explicit operator RawstorIOQueue*() noexcept;

        void wait();
};


Queue::Queue(int operations, unsigned int depth):
    _operations(operations),
    _impl(nullptr)
{
    _impl = rawstor_io_queue_create(depth);
    if (_impl == nullptr) {
        RAWSTOR_THROW_ERRNO();
    }
}

Queue::~Queue() {
    rawstor_io_queue_delete(_impl);
}


int Queue::callback(
    RawstorObject *,
    size_t size, size_t res, int error, void *data) noexcept
{
    Queue *queue = static_cast<Queue*>(data);

    --queue->_operations;

    if (error) {
        return -error;
    }

    if (size != res) {
        return -EIO;
    }

    return 0;
}


Queue::operator RawstorIOQueue*() noexcept {
    return _impl;
}


void Queue::wait() {
    while (_operations > 0) {
        RawstorIOEvent *event = rawstor_io_queue_wait_event_timeout(
            _impl, rawstor_opts_wait_timeout());
        if (event == NULL) {
            if (errno) {
                RAWSTOR_THROW_ERRNO();
            }
            break;
        }

        int res = rawstor_io_event_dispatch(event);
        if (res < 0) {
            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }

        rawstor_io_queue_release_event(_impl, event);
    }

    if (_operations > 0) {
        throw std::runtime_error("Queue not completed");
    }
}


} // unnamed namespace


namespace rawstor {


class ConnectionOp {
    private:
        RawstorCallback *_cb;
        void *_data;

    protected:
        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept
        {
            ConnectionOp *op = static_cast<ConnectionOp*>(data);

            int ret = op->callback(object, size, res, error);

            delete op;

            return ret;
        }

    public:
        ConnectionOp(RawstorCallback *cb, void *data):
            _cb(cb),
            _data(data)
        {}
        ConnectionOp(const ConnectionOp &) = delete;
        ConnectionOp(ConnectionOp &&) = delete;
        ConnectionOp& operator=(const ConnectionOp &) = delete;
        ConnectionOp& operator=(ConnectionOp &&) = delete;
        virtual ~ConnectionOp() {}

        virtual void operator()(const std::shared_ptr<Socket> &s) = 0;

        inline int callback(
            RawstorObject *object, size_t size, size_t res, int error)
        {
            return _cb(object, size, res, error, _data);
        }
};


class ConnectionOpPRead: public ConnectionOp {
    private:
        void *_buf;
        size_t _size;
        size_t _offset;
        std::shared_ptr<Socket> _s;

    public:
        ConnectionOpPRead(
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<Socket> &s) {
            _s = s;
            _s->pread(_buf, _size, _offset, _process, this);
        }
};


class ConnectionOpPReadV: public ConnectionOp {
    private:
        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;
        std::shared_ptr<Socket> _s;

    public:
        ConnectionOpPReadV(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<Socket> &s) {
            _s = s;
            _s->preadv(_iov, _niov, _size, _offset, _process, this);
        }
};


class ConnectionOpPWrite: public ConnectionOp {
    private:
        void *_buf;
        size_t _size;
        size_t _offset;
        std::shared_ptr<Socket> _s;

    public:
        ConnectionOpPWrite(
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<Socket> &s) {
            _s = s;
            _s->pwrite(_buf, _size, _offset, _process, this);
        }
};


class ConnectionOpPWriteV: public ConnectionOp {
    private:
        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;
        std::shared_ptr<Socket> _s;

    public:
        ConnectionOpPWriteV(
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<Socket> &s) {
            _s = s;
            _s->pwritev(_iov, _niov, _size, _offset, _process, this);
        }
};


Connection::Connection(unsigned int depth):
    _depth(depth),
    _socket_index(0)
{}


Connection::~Connection() {
    try {
        close();
    } catch (const std::system_error &e) {
        rawstor_error("Connection::close(): %s\n", e.what());
    }
}


std::shared_ptr<Socket> Connection::_get_next_socket() {
    if (_sockets.empty()) {
        throw std::runtime_error("Empty sockets list");
    }

    std::shared_ptr<Socket> s = _sockets[_socket_index++];
    if (_socket_index >= _sockets.size()) {
        _socket_index = 0;
    }

    return s;
}


void Connection::create(
    const SocketAddress &ost,
    const RawstorObjectSpec &sp, RawstorUUID *id)
{
    Queue q(1, _depth);

    Socket s(ost, _depth);
    s.create(static_cast<RawstorIOQueue*>(q), sp, id, q.callback, &q);

    q.wait();
}


void Connection::remove(
    const SocketAddress &ost,
    const RawstorUUID &id)
{
    Queue q(1, _depth);

    Socket s(ost, _depth);
    s.remove(static_cast<RawstorIOQueue*>(q), id, q.callback, &q);

    q.wait();
}


void Connection::spec(
    const SocketAddress &ost,
    const RawstorUUID &id, RawstorObjectSpec *sp)
{
    Queue q(1, _depth);

    Socket s(ost, _depth);
    s.spec(static_cast<RawstorIOQueue*>(q), id, sp, q.callback, &q);

    q.wait();
}


void Connection::open(
    const SocketAddress &ost,
    rawstor::Object *object,
    size_t sockets)
{
    Queue q(sockets, _depth);

    try {
        _sockets.reserve(sockets);
        for (size_t i = 0; i < sockets; ++i) {
            _sockets.push_back(
                std::shared_ptr<Socket>(new Socket(ost, _depth)));
        }

        for (std::shared_ptr<Socket> s: _sockets) {
            s->set_object(
                static_cast<RawstorIOQueue*>(q), object, q.callback, &q);
        }

        q.wait();
    } catch (...) {
        _sockets.clear();
        throw;
    }
}


void Connection::close() {
    _sockets.clear();
}


void Connection::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOpPRead> op(
        new ConnectionOpPRead(buf, size, offset, cb, data));
    (*op)(s);
    op.release();
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOpPReadV> op(
        new ConnectionOpPReadV(iov, niov, size, offset, cb, data));
    (*op)(s);
    op.release();
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOpPWrite> op(
        new ConnectionOpPWrite(buf, size, offset, cb, data));
    (*op)(s);
    op.release();
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOpPWriteV> op(
        new ConnectionOpPWriteV(iov, niov, size, offset, cb, data));
    (*op)(s);
    op.release();
}


} // rawstor
