#include "connection.hpp"

#include "driver.hpp"
#include "opts.h"

#include <rawstorio/event.hpp>
#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>

#include <rawstor/object.h>

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cstring>


namespace rawstor {


class ConnectionOp {
    private:
        Connection &_cn;
        RawstorCallback *_cb;
        void *_data;

    protected:
        std::shared_ptr<Driver> _s;
        unsigned int _attempts;

        static int _submit_cb(
            RawstorObject *object,
            size_t size, size_t res, int error, void *data) noexcept;

    public:
        ConnectionOp(Connection &cn, RawstorCallback *cb, void *data);
        ConnectionOp(const ConnectionOp &) = delete;
        ConnectionOp(ConnectionOp &&) = delete;
        virtual ~ConnectionOp() {}
        ConnectionOp& operator=(const ConnectionOp &) = delete;
        ConnectionOp& operator=(ConnectionOp &&) = delete;

        virtual void submit(const std::shared_ptr<Driver> &s) = 0;

        virtual std::string str() const = 0;

        inline int dispatch(
            RawstorObject *object, size_t size, size_t res, int error)
        {
            return _cb(object, size, res, error, _data);
        }
};


} // rawstor


namespace {


/**
 * TODO: Remove this class.
 */
class Queue {
    private:
        int _operations;
        std::unique_ptr<rawstor::io::Queue> _q;

    public:
        static int callback(
            RawstorObject *,
            size_t size, size_t res, int error, void *data) noexcept;

        Queue(int operations, unsigned int depth);
        Queue(const Queue &) = delete;

        Queue& operator=(const Queue &) = delete;

        inline rawstor::io::Queue& queue() noexcept {
            return *_q;
        }

        void wait();
};


Queue::Queue(int operations, unsigned int depth):
    _operations(operations),
    _q(rawstor::io::Queue::create(depth))
{}


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


void Queue::wait() {
    while (_operations > 0) {
        RawstorIOEvent *event = _q->wait_event(rawstor_opts_wait_timeout());
        if (event == NULL) {
            break;
        }

        event->dispatch();

        _q->release_event(event);
    }

    if (_operations > 0) {
        throw std::runtime_error("Queue not completed");
    }
}


class ConnectionOpPRead: public rawstor::ConnectionOp {
    private:
        void *_buf;
        size_t _size;
        size_t _offset;

    public:
        ConnectionOpPRead(
            rawstor::Connection &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void submit(const std::shared_ptr<rawstor::Driver> &s) {
            _s = s;
            ++_attempts;
            _s->pread(_buf, _size, _offset, _submit_cb, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pread: size = " << _size << ", offset = " << _offset;
            return oss.str();
        }
};


class ConnectionOpPReadV: public rawstor::ConnectionOp {
    private:
        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        ConnectionOpPReadV(
            rawstor::Connection &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void submit(const std::shared_ptr<rawstor::Driver> &s) {
            _s = s;
            ++_attempts;
            _s->preadv(_iov, _niov, _size, _offset, _submit_cb, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO preadv: size = " << _size << ", offset = " << _offset;
            return oss.str();
        }
};


class ConnectionOpPWrite: public rawstor::ConnectionOp {
    private:
        void *_buf;
        size_t _size;
        size_t _offset;

    public:
        ConnectionOpPWrite(
            rawstor::Connection &cn,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
            _buf(buf),
            _size(size),
            _offset(offset)
        {}

        void submit(const std::shared_ptr<rawstor::Driver> &s) {
            _s = s;
            ++_attempts;
            _s->pwrite(_buf, _size, _offset, _submit_cb, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pwrite: size = " << _size << ", offset = " << _offset;
            return oss.str();
        }
};


class ConnectionOpPWriteV: public rawstor::ConnectionOp {
    private:
        iovec *_iov;
        unsigned int _niov;
        size_t _size;
        off_t _offset;

    public:
        ConnectionOpPWriteV(
            rawstor::Connection &cn,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, cb, data),
            _iov(iov),
            _niov(niov),
            _size(size),
            _offset(offset)
        {}

        void submit(const std::shared_ptr<rawstor::Driver> &s) {
            _s = s;
            ++_attempts;
            _s->pwritev(_iov, _niov, _size, _offset, _submit_cb, this);
        }

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pwritev: size = " << _size << ", offset = " << _offset;
            return oss.str();
        }
};


} // unnamed

namespace rawstor {


ConnectionOp::ConnectionOp(rawstor::Connection &cn, RawstorCallback *cb, void *data):
    _cn(cn),
    _cb(cb),
    _data(data),
    _attempts(0)
{}


int ConnectionOp::_submit_cb(
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
                op->_cn.invalidate_session(op->_s);
                op->_cn.retry(op);
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

    int ret = op->dispatch(object, size, res, error);

    delete op;

    return ret;
}


Connection::Connection(unsigned int depth):
    _object(nullptr),
    _depth(depth),
    _session_index(0)
{}


Connection::~Connection() {
    try {
        close();
    } catch (const std::system_error &e) {
        rawstor_error("Connection::close(): %s\n", e.what());
    }
}


std::vector<std::shared_ptr<Driver>> Connection::_open(
    const URI &uri,
    RawstorObject *object,
    size_t nsessions)
{
    std::vector<std::shared_ptr<Driver>> sessions;

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
                sessions.push_back(Driver::create(uri, _depth));
            }

            for (std::shared_ptr<Driver> s: sessions) {
                s->set_object(q.queue(), object, q.callback, &q);
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


std::shared_ptr<Driver> Connection::_get_next_session() {
    if (_sessions.empty()) {
        throw std::runtime_error("Empty sessions list");
    }

    std::shared_ptr<Driver> s = _sessions[_session_index++];
    if (_session_index >= _sessions.size()) {
        _session_index = 0;
    }

    return s;
}


void Connection::invalidate_session(const std::shared_ptr<Driver> &s) {
    typename std::vector<std::shared_ptr<Driver>>::iterator it = std::find(
        _sessions.begin(), _sessions.end(), s);

    if (it != _sessions.end()) {
        _sessions.erase(it);

        std::vector<std::shared_ptr<Driver>> new_sessions = _open(
            s->uri(), _object, 1);

        _sessions.push_back(new_sessions.front());
    }
}


void Connection::create(
    const URI &uri,
    const RawstorObjectSpec &sp, RawstorUUID *id)
{
    Queue q(1, _depth);

    std::unique_ptr<Driver> s = Driver::create(uri, _depth);
    s->create(q.queue(), sp, id, q.callback, &q);

    q.wait();
}


void Connection::remove(const URI &uri) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Driver> s = Driver::create(uri.up(), _depth);
    s->remove(q.queue(), id, q.callback, &q);

    q.wait();
}


void Connection::spec(const URI &uri, RawstorObjectSpec *sp) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Driver> s = Driver::create(uri.up(), _depth);
    s->spec(q.queue(), id, sp, q.callback, &q);

    q.wait();
}


void Connection::open(
    const URI &uri,
    RawstorObject *object,
    size_t nsessions)
{
    _sessions = _open(uri, object, nsessions);
    _object = object;
}


void Connection::close() {
    _sessions.clear();
    _object = nullptr;
}


void Connection::pread(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<ConnectionOpPRead> op =
        std::make_unique<ConnectionOpPRead>(
            *this, buf, size, offset, cb, data);
    op->submit(_get_next_session());
    op.release();
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<ConnectionOpPReadV> op =
        std::make_unique<ConnectionOpPReadV>(
            *this, iov, niov, size, offset, cb, data);
    op->submit(_get_next_session());
    op.release();
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<ConnectionOpPWrite> op =
        std::make_unique<ConnectionOpPWrite>(
            *this, buf, size, offset, cb, data);
    op->submit(_get_next_session());
    op.release();
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::unique_ptr<ConnectionOpPWriteV> op =
        std::make_unique<ConnectionOpPWriteV>(
            *this, iov, niov, size, offset, cb, data);
    op->submit(_get_next_session());
    op.release();
}


void Connection::retry(ConnectionOp *op) {
    op->submit(_get_next_session());
}


} // rawstor
