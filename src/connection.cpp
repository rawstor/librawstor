#include "connection.hpp"

#include "opts.h"
#include "socket.hpp"

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor/object.h>

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


struct ConnectionOp {
    Connection *cn;
    std::shared_ptr<Socket> s;

    RawstorCallback *callback;
    void *data;
};


Connection::Connection(unsigned int depth):
    _depth(depth),
    _ops(_depth),
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


ConnectionOp* Connection::_acquire_op() {
    return _ops.alloc();
}


void Connection::_release_op(ConnectionOp* op) noexcept {
    op->s.reset();
    _ops.free(op);
}


int Connection::_process(
    RawstorObject *object,
    size_t size, size_t res, int error, void *data) noexcept
{
    ConnectionOp *op = static_cast<ConnectionOp*>(data);

    int ret = op->callback(object, size, res, error, op->data);

    op->cn->_release_op(op);

    return ret;
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
    ConnectionOp *op = _acquire_op();
    try {
        *op = {
            .cn = this,
            .s = s,
            .callback = cb,
            .data = data,
        };
        s->pread(buf, size, offset, _process, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    ConnectionOp *op = _acquire_op();
    try {
        *op = {
            .cn = this,
            .s = s,
            .callback = cb,
            .data = data,
        };
        s->preadv(iov, niov, size, offset, _process, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    ConnectionOp *op = _acquire_op();
    try {
        *op = {
            .cn = this,
            .s = s,
            .callback = cb,
            .data = data,
        };
        s->pwrite(buf, size, offset, _process, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    ConnectionOp *op = _acquire_op();
    try {
        *op = {
            .cn = this,
            .s = s,
            .callback = cb,
            .data = data,
        };
        s->pwritev(iov, niov, size, offset, _process, op);
    } catch (...) {
        _release_op(op);
        throw;
    }
}


} // rawstor
