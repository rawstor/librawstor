#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "opts.h"

#include <rawstorstd/logging.h>
#include <rawstorstd/socket_address.hpp>

#include <rawstorio/queue.h>

#include <rawstor/object.h>
#include <rawstor/rawstor.h>

#include <algorithm>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#include <cstddef>
#include <cstring>

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


template <class DriverImpl>
class ConnectionOp;

class Object;


template <class DriverImpl>
class Connection {
    friend class ConnectionOp<DriverImpl>;

    private:
        Object *_object;
        unsigned int _depth;

        std::vector<std::shared_ptr<DriverImpl>> _sessions;
        size_t _session_index;

        std::vector<std::shared_ptr<DriverImpl>> _open(
            const SocketAddress &ost,
            rawstor::Object *object,
            size_t nsessions);

        void _replace_session(const std::shared_ptr<DriverImpl> &s);
        std::shared_ptr<DriverImpl> _get_next_session();

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
            size_t nsessions);

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


template <class DriverImpl>
class ConnectionOp {
    private:
        Connection<DriverImpl> &_cn;
        RawstorCallback *_cb;
        void *_data;

    protected:
        std::shared_ptr<DriverImpl> _s;
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
                        op->_cn._replace_session(op->_s);
                        (*op)(op->_cn._get_next_session());
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
            Connection<DriverImpl> &cn, RawstorCallback *cb, void *data):
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

        virtual void operator()(const std::shared_ptr<DriverImpl> &s) = 0;

        virtual std::string str() const = 0;

        inline int callback(
            RawstorObject *object, size_t size, size_t res, int error)
        {
            return _cb(object, size, res, error, _data);
        }
};


template <class DriverImpl>
class ConnectionOpPRead: public ConnectionOp<DriverImpl> {
    private:
        using ConnectionOp<DriverImpl>::_s;
        using ConnectionOp<DriverImpl>::_attempts;
        using ConnectionOp<DriverImpl>::_process;

        void *_buf;
        size_t _size;
        size_t _offset;

    public:
        ConnectionOpPRead(
            Connection<DriverImpl> &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<DriverImpl>(cn, cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<DriverImpl> &s) {
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


template <class DriverImpl>
class ConnectionOpPReadV: public ConnectionOp<DriverImpl> {
    private:
        using ConnectionOp<DriverImpl>::_s;
        using ConnectionOp<DriverImpl>::_attempts;
        using ConnectionOp<DriverImpl>::_process;

        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        ConnectionOpPReadV(
            Connection<DriverImpl> &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<DriverImpl>(cn, cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<DriverImpl> &s) {
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


template <class DriverImpl>
class ConnectionOpPWrite: public ConnectionOp<DriverImpl> {
    private:
        using ConnectionOp<DriverImpl>::_s;
        using ConnectionOp<DriverImpl>::_attempts;
        using ConnectionOp<DriverImpl>::_process;

        void *_buf;
        size_t _size;
        size_t _offset;

    public:
        ConnectionOpPWrite(
            Connection<DriverImpl> &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<DriverImpl>(cn, cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<DriverImpl> &s) {
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


template <class DriverImpl>
class ConnectionOpPWriteV: public ConnectionOp<DriverImpl> {
    private:
        using ConnectionOp<DriverImpl>::_s;
        using ConnectionOp<DriverImpl>::_attempts;
        using ConnectionOp<DriverImpl>::_process;

        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        ConnectionOpPWriteV(
            Connection<DriverImpl> &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp<DriverImpl>(cn, cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void operator()(const std::shared_ptr<DriverImpl> &s) {
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


template <class DriverImpl>
Connection<DriverImpl>::Connection(unsigned int depth):
    _object(nullptr),
    _depth(depth),
    _session_index(0)
{}


template <class DriverImpl>
Connection<DriverImpl>::~Connection() {
    try {
        close();
    } catch (const std::system_error &e) {
        rawstor_error("Connection::close(): %s\n", e.what());
    }
}


template <class DriverImpl>
std::vector<std::shared_ptr<DriverImpl>> Connection<DriverImpl>::_open(
    const SocketAddress &ost,
    rawstor::Object *object,
    size_t nsessions)
{
    std::vector<std::shared_ptr<DriverImpl>> sessions;

    for (
        unsigned int attempt = 1;
        attempt <= rawstor_opts_io_attempts();
        ++attempt)
    {
        try {
            Queue q(nsessions, _depth);

            sessions.clear();
            sessions.reserve(nsessions);
            for (size_t i = 0; i < nsessions; ++i) {
                sessions.push_back(std::make_shared<DriverImpl>(ost, _depth));
            }

            for (std::shared_ptr<DriverImpl> s: sessions) {
                s->set_object(
                    static_cast<RawstorIOQueue*>(q), object, q.callback, &q);
            }

            q.wait();

            break;
        } catch (const std::system_error &e) {
            if (attempt != rawstor_opts_io_attempts()) {
                rawstor_warning(
                    "Open session failed; error: %s; "
                    "attempt: %d of %d; retrying...\n",
                    e.what(),
                    attempt, rawstor_opts_io_attempts());
            } else {
                rawstor_warning(
                    "Open session failed; error: %s; "
                    "attempt: %d of %d; failing...\n",
                    e.what(),
                    attempt, rawstor_opts_io_attempts());
                throw;
            }
        }
    }

    return sessions;
}


template <class DriverImpl>
void Connection<DriverImpl>::_replace_session(
    const std::shared_ptr<DriverImpl> &s)
{
    typename std::vector<std::shared_ptr<DriverImpl>>::iterator it = std::find(
        _sessions.begin(), _sessions.end(), s);

    if (it != _sessions.end()) {
        _sessions.erase(it);

        std::vector<std::shared_ptr<DriverImpl>> new_sessions = _open(
            s->ost(), _object, 1);

        _sessions.push_back(new_sessions.front());
    }
}


template <class DriverImpl>
std::shared_ptr<DriverImpl> Connection<DriverImpl>::_get_next_session() {
    if (_sessions.empty()) {
        throw std::runtime_error("Empty sessions list");
    }

    std::shared_ptr<DriverImpl> s = _sessions[_session_index++];
    if (_session_index >= _sessions.size()) {
        _session_index = 0;
    }

    return s;
}


template <class DriverImpl>
void Connection<DriverImpl>::create(
    const SocketAddress &ost,
    const RawstorObjectSpec &sp, RawstorUUID *id)
{
    Queue q(1, _depth);

    DriverImpl s(ost, _depth);
    s.create(static_cast<RawstorIOQueue*>(q), sp, id, q.callback, &q);

    q.wait();
}


template <class DriverImpl>
void Connection<DriverImpl>::remove(
    const SocketAddress &ost,
    const RawstorUUID &id)
{
    Queue q(1, _depth);

    DriverImpl s(ost, _depth);
    s.remove(static_cast<RawstorIOQueue*>(q), id, q.callback, &q);

    q.wait();
}


template <class DriverImpl>
void Connection<DriverImpl>::spec(
    const SocketAddress &ost,
    const RawstorUUID &id, RawstorObjectSpec *sp)
{
    Queue q(1, _depth);

    DriverImpl s(ost, _depth);
    s.spec(static_cast<RawstorIOQueue*>(q), id, sp, q.callback, &q);

    q.wait();
}


template <class DriverImpl>
void Connection<DriverImpl>::open(
    const SocketAddress &ost,
    rawstor::Object *object,
    size_t nsessions)
{
    _sessions = _open(ost, object, nsessions);
    _object = object;
}


template <class DriverImpl>
void Connection<DriverImpl>::close() {
    _sessions.clear();
    _object = nullptr;
}


template <class DriverImpl>
void Connection<DriverImpl>::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<DriverImpl> s = _get_next_session();
    std::unique_ptr<ConnectionOp<DriverImpl>> op =
        std::make_unique<ConnectionOpPRead<DriverImpl>>(
            *this, buf, size, offset, cb, data);
            (*op)(s);
    op.release();
}


template <class DriverImpl>
void Connection<DriverImpl>::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<DriverImpl> s = _get_next_session();
    std::unique_ptr<ConnectionOp<DriverImpl>> op =
        std::make_unique<ConnectionOpPReadV<DriverImpl>>(
            *this, iov, niov, size, offset, cb, data);
    (*op)(s);
    op.release();
}


template <class DriverImpl>
void Connection<DriverImpl>::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<DriverImpl> s = _get_next_session();
    std::unique_ptr<ConnectionOp<DriverImpl>> op =
        std::make_unique<ConnectionOpPWrite<DriverImpl>>(
            *this, buf, size, offset, cb, data);
    (*op)(s);
    op.release();
}


template <class DriverImpl>
void Connection<DriverImpl>::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<DriverImpl> s = _get_next_session();
    std::unique_ptr<ConnectionOp<DriverImpl>> op =
        std::make_unique<ConnectionOpPWriteV<DriverImpl>>(
            *this, iov, niov, size, offset, cb, data);
    (*op)(s);
    op.release();
}


} // rawstor

#endif // RAWSTOR_CONNECTION_HPP
