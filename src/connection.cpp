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
#include <cstring>

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
        Connection &_cn;
        int _attempts;
        RawstorCallback *_cb;
        void *_data;

    protected:
        std::shared_ptr<Socket> _s;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept
        {
            static int max_attempts = 3;

            ConnectionOp *op = static_cast<ConnectionOp*>(data);

            if (error) {
                if (op->_attempts < max_attempts) {
                    ++op->_attempts;
                    rawstor_error(
                        "IO error: %s, attempt %d of %d, retrying...\n",
                        strerror(error), op->_attempts, max_attempts);
                    try {
                        op->_cn._replace_socket(op->_s);
                        (*op)(op->_cn._get_next_socket());
                    } catch (const std::system_error &e) {
                        return -e.code().value();
                    }
                    return 0;
                } else {
                    rawstor_error(
                        "IO error: %s, attempt %d of %d, failing...\n",
                        strerror(error), op->_attempts, max_attempts);
                }
            }

            int ret = op->callback(object, size, res, error);

            delete op;

            return ret;
        }

    public:
        ConnectionOp(Connection &cn, RawstorCallback *cb, void *data):
            _cn(cn),
            _attempts(0),
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

    public:
        ConnectionOpPRead(
            Connection &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
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

    public:
        ConnectionOpPReadV(
            Connection &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
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

    public:
        ConnectionOpPWrite(
            Connection &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
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

    public:
        ConnectionOpPWriteV(
            Connection &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
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
    _object(nullptr),
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


void Connection::_replace_socket(const std::shared_ptr<Socket> &s) {
    bool found = false;

    std::vector<std::shared_ptr<Socket>>::iterator end = _sockets.end();
    for (
        std::vector<std::shared_ptr<Socket>>::iterator it = _sockets.begin();
        it != end;
        ++it)
    {
        if (*it == s) {
            found = true;
            _sockets.erase(it);
            break;
        }
    }

    if (found) {
        Queue q(1, _depth);
        std::shared_ptr<Socket> new_socket(new Socket(s->ost(), _depth));

        new_socket->set_object(
            static_cast<RawstorIOQueue*>(q), _object, q.callback, &q);

        q.wait();

        _sockets.push_back(new_socket);
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

    _object = object;
}


void Connection::close() {
    _sockets.clear();
    _object = nullptr;
}


void Connection::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op(
        new ConnectionOpPRead(*this, buf, size, offset, cb, data));
    (*op)(s);
    op.release();
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op(
        new ConnectionOpPReadV(*this, iov, niov, size, offset, cb, data));
    (*op)(s);
    op.release();
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op(
        new ConnectionOpPWrite(*this, buf, size, offset, cb, data));
    (*op)(s);
    op.release();
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op(
        new ConnectionOpPWriteV(*this, iov, niov, size, offset, cb, data));
    (*op)(s);
    op.release();
}


} // rawstor
