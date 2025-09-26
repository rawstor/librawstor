#include "connection.hpp"

#include "opts.h"
#include "socket.hpp"

#include <rawstorio/event.h>
#include <rawstorio/queue.h>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor/object.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

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
        RawstorCallback *_cb;
        void *_data;

    protected:
        std::shared_ptr<Socket> _s;
        unsigned int _attempts;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept
        {
            ConnectionOp *op = static_cast<ConnectionOp*>(data);

            if (error) {
                if (op->_attempts < rawstor_opts_io_attempts()) {
                    rawstor_warning(
                        "%s; error on %s: %s; attempt: %d of %d; retrying...\n",
                        op->str().c_str(), op->_s->str().c_str(),
                        std::strerror(error),
                        op->_attempts, rawstor_opts_io_attempts());
                    try {
                        op->_cn._replace_socket(op->_s);
                        (*op)(op->_cn._get_next_socket());
                        return 0;
                    } catch (const std::system_error &e) {
                        error = e.code().value();
                    }
                } else {
                    rawstor_error(
                        "%s; error on %s: %s; attempt %d of %d; failing...\n",
                        op->str().c_str(), op->_s->str().c_str(),
                        std::strerror(error),
                        op->_attempts, rawstor_opts_io_attempts());
                }
            } else {
                if (op->_attempts > 1) {
                    rawstor_warning(
                        "%s; success on %s; attempt: %d of %d\n",
                        op->str().c_str(), op->_s->str().c_str(),
                        op->_attempts, rawstor_opts_io_attempts());
                }
            }

            int ret = op->callback(object, size, res, error);

            delete op;

            return ret;
        }

    public:
        ConnectionOp(Connection &cn, RawstorCallback *cb, void *data):
            _cn(cn),
            _cb(cb),
            _data(data),
            _attempts(0)
        {}
        ConnectionOp(const ConnectionOp &) = delete;
        ConnectionOp(ConnectionOp &&) = delete;
        ConnectionOp& operator=(const ConnectionOp &) = delete;
        ConnectionOp& operator=(ConnectionOp &&) = delete;
        virtual ~ConnectionOp() {}

        virtual void operator()(const std::shared_ptr<Socket> &s) = 0;

        virtual std::string str() const = 0;

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
            ++_attempts;
            _s->pread(_buf, _size, _offset, _process, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pread: size = " << _size << ", offset = " << _offset;
            return oss.str();
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
            ++_attempts;
            _s->preadv(_iov, _niov, _size, _offset, _process, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO preadv: size = " << _size << ", offset = " << _offset;
            return oss.str();
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
            ++_attempts;
            _s->pwrite(_buf, _size, _offset, _process, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pwrite: size = " << _size << ", offset = " << _offset;
            return oss.str();
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
            ++_attempts;
            _s->pwritev(_iov, _niov, _size, _offset, _process, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pwritev: size = " << _size << ", offset = " << _offset;
            return oss.str();
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


std::vector<std::shared_ptr<Socket>> Connection::_open(
    const SocketAddress &ost,
    rawstor::Object *object,
    size_t nsockets)
{
    std::vector<std::shared_ptr<Socket>> sockets;

    for (
        unsigned int attempt = 1;
        attempt <= rawstor_opts_io_attempts();
        ++attempt)
    {
        try {
            Queue q(nsockets, _depth);

            sockets.clear();
            sockets.reserve(nsockets);
            for (size_t i = 0; i < nsockets; ++i) {
                sockets.push_back(std::make_shared<Socket>(ost, _depth));
            }

            for (std::shared_ptr<Socket> s: sockets) {
                s->set_object(
                    static_cast<RawstorIOQueue*>(q), object, q.callback, &q);
            }

            q.wait();

            break;
        } catch (const std::system_error &e) {
            if (attempt != rawstor_opts_io_attempts()) {
                rawstor_warning(
                    "Open socket failed; error: %s; "
                    "attempt: %d of %d; retrying...\n",
                    e.what(),
                    attempt, rawstor_opts_io_attempts());
            } else {
                rawstor_warning(
                    "Open socket failed; error: %s; "
                    "attempt: %d of %d; failing...\n",
                    e.what(),
                    attempt, rawstor_opts_io_attempts());
                throw;
            }
        }
    }

    return sockets;
}


void Connection::_replace_socket(const std::shared_ptr<Socket> &s) {
    std::vector<std::shared_ptr<Socket>>::iterator it = std::find(
        _sockets.begin(), _sockets.end(), s);

    if (it != _sockets.end()) {
        _sockets.erase(it);

        std::vector<std::shared_ptr<Socket>> new_sockets = _open(
            s->ost(), _object, 1);

        _sockets.push_back(new_sockets.front());
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
    size_t nsockets)
{
    _sockets = _open(ost, object, nsockets);
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
    std::unique_ptr<ConnectionOp> op = std::make_unique<ConnectionOpPRead>(
        *this, buf, size, offset, cb, data);
    (*op)(s);
    op.release();
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op = std::make_unique<ConnectionOpPReadV>(
        *this, iov, niov, size, offset, cb, data);
    (*op)(s);
    op.release();
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op = std::make_unique<ConnectionOpPWrite>(
        *this, buf, size, offset, cb, data);
    (*op)(s);
    op.release();
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<Socket> s = _get_next_socket();
    std::unique_ptr<ConnectionOp> op = std::make_unique<ConnectionOpPWriteV>(
        *this, iov, niov, size, offset, cb, data);
    (*op)(s);
    op.release();
}


} // rawstor
