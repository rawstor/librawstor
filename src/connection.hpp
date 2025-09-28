#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "opts.h"

#include <rawstorstd/logging.h>
#include <rawstorstd/socket_address.hpp>

#include <rawstorio/queue.h>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <memory>
#include <sstream>
#include <string>
#include <vector>

#include <cstddef>

namespace rawstor {


/**
 * TODO: Remove this class.
 */
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


template <class SocketImpl>
class ConnectionOp;

class Object;


template <class SocketImpl>
class Connection {
    friend class ConnectionOp<SocketImpl>;

    private:
        Object *_object;
        unsigned int _depth;

        std::vector<std::shared_ptr<SocketImpl>> _sockets;
        size_t _socket_index;

        std::vector<std::shared_ptr<SocketImpl>> _open(
            const SocketAddress &ost,
            rawstor::Object *object,
            size_t nsockets);

        void _replace_socket(const std::shared_ptr<SocketImpl> &s);
        std::shared_ptr<SocketImpl> _get_next_socket();

    public:
        Connection(unsigned int depth);
        Connection(const Connection &) = delete;
        ~Connection();

        Connection& operator=(const Connection&) = delete;

        void create(
            const SocketAddress &ost,
            const RawstorObjectSpec &sp, RawstorUUID *id);

        void remove(
            const SocketAddress &ost,
            const RawstorUUID &id);

        void spec(
            const SocketAddress &ost,
            const RawstorUUID &id, RawstorObjectSpec *sp);

        void open(
            const SocketAddress &ost,
            rawstor::Object *object,
            size_t nsockets);

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


template <class SocketImpl>
class ConnectionOp {
    private:
        Connection<SocketImpl> &_cn;
        RawstorCallback *_cb;
        void *_data;

    protected:
        std::shared_ptr<SocketImpl> _s;
        unsigned int _attempts;

        static int _process(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept
        {
            ConnectionOp *op = static_cast<ConnectionOp*>(data);

            if (error) {
                if (op->_attempts < rawstor_opts_io_attempts()) {
                    rawstor_warning(
                        "%s; error on %s: %s; attempt: %d of %d; "
                        "retrying...\n",
                        op->str().c_str(), op->_s->str().c_str(),
                        std::strerror(error),
                        op->_attempts, rawstor_opts_io_attempts());
                    try {
                        op->_cn._replace_socket(op->_s);
                        (*op)(op->_cn._get_next_socket());
                        return 0;
                    } catch (const std::system_error &e) {
                        error = e.code().value();
                    } catch (const std::exception &e) {
                        rawstor_error(
                            "%s; exception on %s: %s; attempt %d of %d; "
                            "failing...\n",
                            op->str().c_str(), op->_s->str().c_str(),
                            e.what(),
                            op->_attempts, rawstor_opts_io_attempts());
                        error = EIO;
                    }
                } else {
                    rawstor_error(
                        "%s; error on %s: %s; attempt %d of %d; "
                        "failing...\n",
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
        ConnectionOp(
            Connection<SocketImpl> &cn, RawstorCallback *cb, void *data):
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

        virtual void operator()(const std::shared_ptr<SocketImpl> &s) = 0;

        virtual std::string str() const = 0;

        inline int callback(
            RawstorObject *object, size_t size, size_t res, int error)
        {
            return _cb(object, size, res, error, _data);
        }
};


template <class SocketImpl>
class ConnectionOpPRead: public ConnectionOp<SocketImpl> {
    private:
        using ConnectionOp<SocketImpl>::_s;
        using ConnectionOp<SocketImpl>::_attempts;
        using ConnectionOp<SocketImpl>::_process;

        void *_buf;
        size_t _size;
        size_t _offset;

    public:
        ConnectionOpPRead(
            Connection<SocketImpl> &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<SocketImpl>(cn, cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<SocketImpl> &s) {
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


template <class SocketImpl>
class ConnectionOpPReadV: public ConnectionOp<SocketImpl> {
    private:
        using ConnectionOp<SocketImpl>::_s;
        using ConnectionOp<SocketImpl>::_attempts;
        using ConnectionOp<SocketImpl>::_process;

        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        ConnectionOpPReadV(
            Connection<SocketImpl> &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<SocketImpl>(cn, cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<SocketImpl> &s) {
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


template <class SocketImpl>
class ConnectionOpPWrite: public ConnectionOp<SocketImpl> {
    private:
        using ConnectionOp<SocketImpl>::_s;
        using ConnectionOp<SocketImpl>::_attempts;
        using ConnectionOp<SocketImpl>::_process;

        void *_buf;
        size_t _size;
        size_t _offset;

    public:
        ConnectionOpPWrite(
            Connection<SocketImpl> &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<SocketImpl>(cn, cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<SocketImpl> &s) {
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


template <class SocketImpl>
class ConnectionOpPWriteV: public ConnectionOp<SocketImpl> {
    private:
        using ConnectionOp<SocketImpl>::_s;
        using ConnectionOp<SocketImpl>::_attempts;
        using ConnectionOp<SocketImpl>::_process;

        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        ConnectionOpPWriteV(
            Connection<SocketImpl> &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<SocketImpl>(cn, cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<SocketImpl> &s) {
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


template <class SocketImpl>
Connection<SocketImpl>::Connection(unsigned int depth):
    _object(nullptr),
    _depth(depth),
    _socket_index(0)
{}


template <class SocketImpl>
Connection<SocketImpl>::~Connection() {
    try {
        close();
    } catch (const std::system_error &e) {
        rawstor_error("Connection::close(): %s\n", e.what());
    }
}


template <class SocketImpl>
std::vector<std::shared_ptr<SocketImpl>> Connection<SocketImpl>::_open(
    const SocketAddress &ost,
    rawstor::Object *object,
    size_t nsockets)
{
    std::vector<std::shared_ptr<SocketImpl>> sockets;

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
                sockets.push_back(std::make_shared<SocketImpl>(ost, _depth));
            }

            for (std::shared_ptr<SocketImpl> s: sockets) {
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


template <class SocketImpl>
void Connection<SocketImpl>::_replace_socket(
    const std::shared_ptr<SocketImpl> &s)
{
    typename std::vector<std::shared_ptr<SocketImpl>>::iterator it = std::find(
        _sockets.begin(), _sockets.end(), s);

    if (it != _sockets.end()) {
        _sockets.erase(it);

        std::vector<std::shared_ptr<SocketImpl>> new_sockets = _open(
            s->ost(), _object, 1);

        _sockets.push_back(new_sockets.front());
    }
}


template <class SocketImpl>
std::shared_ptr<SocketImpl> Connection<SocketImpl>::_get_next_socket() {
    if (_sockets.empty()) {
        throw std::runtime_error("Empty sockets list");
    }

    std::shared_ptr<SocketImpl> s = _sockets[_socket_index++];
    if (_socket_index >= _sockets.size()) {
        _socket_index = 0;
    }

    return s;
}


template <class SocketImpl>
void Connection<SocketImpl>::create(
    const SocketAddress &ost,
    const RawstorObjectSpec &sp, RawstorUUID *id)
{
    Queue q(1, _depth);

    SocketImpl s(ost, _depth);
    s.create(static_cast<RawstorIOQueue*>(q), sp, id, q.callback, &q);

    q.wait();
}


template <class SocketImpl>
void Connection<SocketImpl>::remove(
    const SocketAddress &ost,
    const RawstorUUID &id)
{
    Queue q(1, _depth);

    SocketImpl s(ost, _depth);
    s.remove(static_cast<RawstorIOQueue*>(q), id, q.callback, &q);

    q.wait();
}


template <class SocketImpl>
void Connection<SocketImpl>::spec(
    const SocketAddress &ost,
    const RawstorUUID &id, RawstorObjectSpec *sp)
{
    Queue q(1, _depth);

    SocketImpl s(ost, _depth);
    s.spec(static_cast<RawstorIOQueue*>(q), id, sp, q.callback, &q);

    q.wait();
}


template <class SocketImpl>
void Connection<SocketImpl>::open(
    const SocketAddress &ost,
    rawstor::Object *object,
    size_t nsockets)
{
    _sockets = _open(ost, object, nsockets);
    _object = object;
}


template <class SocketImpl>
void Connection<SocketImpl>::close() {
    _sockets.clear();
    _object = nullptr;
}


template <class SocketImpl>
void Connection<SocketImpl>::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<SocketImpl> s = _get_next_socket();
    std::unique_ptr<ConnectionOp<SocketImpl>> op =
        std::make_unique<ConnectionOpPRead<SocketImpl>>(
            *this, buf, size, offset, cb, data);
            (*op)(s);
    op.release();
}


template <class SocketImpl>
void Connection<SocketImpl>::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<SocketImpl> s = _get_next_socket();
    std::unique_ptr<ConnectionOp<SocketImpl>> op =
        std::make_unique<ConnectionOpPReadV<SocketImpl>>(
            *this, iov, niov, size, offset, cb, data);
    (*op)(s);
    op.release();
}


template <class SocketImpl>
void Connection<SocketImpl>::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<SocketImpl> s = _get_next_socket();
    std::unique_ptr<ConnectionOp<SocketImpl>> op =
        std::make_unique<ConnectionOpPWrite<SocketImpl>>(
            *this, buf, size, offset, cb, data);
    (*op)(s);
    op.release();
}


template <class SocketImpl>
void Connection<SocketImpl>::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<SocketImpl> s = _get_next_socket();
    std::unique_ptr<ConnectionOp<SocketImpl>> op =
        std::make_unique<ConnectionOpPWriteV<SocketImpl>>(
            *this, iov, niov, size, offset, cb, data);
    (*op)(s);
    op.release();
}


} // rawstor

#endif // RAWSTOR_CONNECTION_HPP
