#include "connection.hpp"

#include "opts.h"
#include "session.hpp"
#include "task.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>

#include <rawstor/object.h>

#include <algorithm>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cstring>


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
    while (!_q->empty()) {
        _q->wait(rawstor_opts_wait_timeout());
    }

    if (_operations > 0) {
        throw std::runtime_error("Queue not completed");
    }
}


class ConnectionOp: public rawstor::Task {
    protected:
        rawstor::Connection &_cn;
        std::shared_ptr<rawstor::Session> _s;
        unsigned int _attempt;

        RawstorCallback *_cb;
        void *_data;

        virtual void _retry(const std::shared_ptr<rawstor::Session> &s) = 0;

    public:
        ConnectionOp(
            rawstor::Connection &cn,
            const std::shared_ptr<rawstor::Session> &s,
            unsigned int attempt,
            size_t size,
            RawstorCallback *cb, void *data):
            rawstor::Task(cn.object(), size, cb, data),
            _cn(cn),
            _s(s),
            _attempt(attempt),
            _cb(cb),
            _data(data)
        {}

        ConnectionOp(const ConnectionOp &) = delete;
        ConnectionOp(ConnectionOp &&) = delete;
        virtual ~ConnectionOp() {}
        ConnectionOp& operator=(const ConnectionOp &) = delete;
        ConnectionOp& operator=(ConnectionOp &&) = delete;

        void operator()(size_t result, int error) noexcept;

        virtual std::string str() const = 0;
};


void ConnectionOp::operator()(size_t result, int error) noexcept {
    if (error) {
        if (_attempt < rawstor_opts_io_attempts()) {
            rawstor_warning(
                "%s; error on %s: %s; attempt: %d of %d; "
                "retrying...\n",
                str().c_str(), _s->str().c_str(),
                std::strerror(error),
                _attempt + 1, rawstor_opts_io_attempts());
            try {
                _cn.invalidate_session(_s);
                _retry(_cn.get_next_session());
                return;
            } catch (const std::system_error &e) {
                error = e.code().value();
            } catch (const std::exception &e) {
                rawstor_error(
                    "%s; exception on %s: %s; attempt %d of %d; "
                    "failing...\n",
                    str().c_str(), _s->str().c_str(),
                    e.what(),
                    _attempt + 1, rawstor_opts_io_attempts());
                error = EIO;
            }
        } else {
            rawstor_error(
                "%s; error on %s: %s; attempt %d of %d; "
                "failing...\n",
                str().c_str(), _s->str().c_str(),
                std::strerror(error),
                _attempt + 1, rawstor_opts_io_attempts());
        }
    } else {
        if (_attempt > 0) {
            rawstor_warning(
                "%s; success on %s; attempt: %d of %d\n",
                str().c_str(), _s->str().c_str(),
                _attempt + 1, rawstor_opts_io_attempts());
        }
    }

    rawstor::Task::operator()(result, error);
}


class ConnectionOpPRead: public ConnectionOp {
    private:
        void *_buf;
        size_t _offset;

        void _retry(const std::shared_ptr<rawstor::Session> &s) {
            std::unique_ptr<ConnectionOpPRead> op =
                std::make_unique<ConnectionOpPRead>(
                    _cn, s, _attempt + 1,
                    _buf, _size, _offset, _cb, _data);
            s->pread(_buf, _offset, std::move(op));
        }

    public:
        ConnectionOpPRead(
            rawstor::Connection &cn,
            const std::shared_ptr<rawstor::Session> &s,
            unsigned int attempt,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, s, attempt, size, cb, data),
            _buf(buf),
            _offset(offset)
        {}

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
        off_t _offset;

        void _retry(const std::shared_ptr<rawstor::Session> &s) {
            std::unique_ptr<ConnectionOpPReadV> op =
                std::make_unique<ConnectionOpPReadV>(
                    _cn, s, _attempt + 1,
                    _iov, _niov, _size, _offset, _cb, _data);
            s->preadv(_iov, _niov, _offset, std::move(op));
        }

    public:
        ConnectionOpPReadV(
            rawstor::Connection &cn,
            const std::shared_ptr<rawstor::Session> &s,
            unsigned int attempt,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, s, attempt, size, cb, data),
            _iov(iov),
            _niov(niov),
            _offset(offset)
        {}

        std::string str() const {
            std::ostringstream oss;
            oss << "IO preadv: size = " << _size << ", offset = " << _offset;
            return oss.str();
        }
};


class ConnectionOpPWrite: public ConnectionOp {
    private:
        void *_buf;
        size_t _offset;

        void _retry(const std::shared_ptr<rawstor::Session> &s) {
            std::unique_ptr<ConnectionOpPWrite> op =
                std::make_unique<ConnectionOpPWrite>(
                    _cn, s, _attempt + 1,
                    _buf, _size, _offset, _cb, _data);
            s->pwrite(_buf, _offset, std::move(op));
        }

    public:
        ConnectionOpPWrite(
            rawstor::Connection &cn,
            const std::shared_ptr<rawstor::Session> &s,
            unsigned int attempt,
            void *buf, size_t size, size_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, s, attempt, size, cb, data),
            _buf(buf),
            _offset(offset)
        {}

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
        off_t _offset;

        void _retry(const std::shared_ptr<rawstor::Session> &s) {
            std::unique_ptr<ConnectionOpPWriteV> op =
                std::make_unique<ConnectionOpPWriteV>(
                    _cn, s, _attempt + 1,
                    _iov, _niov, _size, _offset, _cb, _data);
            s->pwritev(_iov, _niov, _offset, std::move(op));
        }

    public:
        ConnectionOpPWriteV(
            rawstor::Connection &cn,
            const std::shared_ptr<rawstor::Session> &s,
            unsigned int attempt,
            iovec *iov, unsigned int niov, size_t size, off_t offset,
            RawstorCallback *cb, void *data):
            ConnectionOp(cn, s, attempt, size, cb, data),
            _iov(iov),
            _niov(niov),
            _offset(offset)
        {}

        std::string str() const {
            std::ostringstream oss;
            oss << "IO pwritev: size = " << _size << ", offset = " << _offset;
            return oss.str();
        }
};


} // unnamed

namespace rawstor {


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


std::vector<std::shared_ptr<Session>> Connection::_open(
    const URI &uri,
    RawstorObject *object,
    size_t nsessions)
{
    std::vector<std::shared_ptr<Session>> sessions;

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
                sessions.push_back(Session::create(uri, _depth));
            }

            for (std::shared_ptr<Session> s: sessions) {
                std::unique_ptr<Task> t =
                    std::make_unique<Task>(object, 0, q.callback, &q);
                s->set_object(q.queue(), object, std::move(t));
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


std::shared_ptr<Session> Connection::get_next_session() {
    if (_sessions.empty()) {
        throw std::runtime_error("Empty sessions list");
    }

    std::shared_ptr<Session> s = _sessions[_session_index++];
    if (_session_index >= _sessions.size()) {
        _session_index = 0;
    }

    return s;
}


void Connection::invalidate_session(const std::shared_ptr<Session> &s) {
    typename std::vector<std::shared_ptr<Session>>::iterator it = std::find(
        _sessions.begin(), _sessions.end(), s);

    if (it != _sessions.end()) {
        _sessions.erase(it);

        std::vector<std::shared_ptr<Session>> new_sessions = _open(
            s->uri(), _object, 1);

        _sessions.push_back(new_sessions.front());
    }
}


void Connection::create(
    const URI &uri,
    const RawstorObjectSpec &sp, RawstorUUID *id)
{
    Queue q(1, _depth);

    std::unique_ptr<Session> s = Session::create(uri, _depth);
    std::unique_ptr<Task> t =
        std::make_unique<Task>(nullptr, 0, q.callback, &q);
    s->create(q.queue(), sp, id, std::move(t));

    q.wait();
}


void Connection::remove(const URI &uri) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s = Session::create(uri.up(), _depth);
    std::unique_ptr<Task> t =
        std::make_unique<Task>(nullptr, 0, q.callback, &q);
    s->remove(q.queue(), id, std::move(t));

    q.wait();
}


void Connection::spec(const URI &uri, RawstorObjectSpec *sp) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s = Session::create(uri.up(), _depth);
    std::unique_ptr<Task> t =
        std::make_unique<Task>(nullptr, 0, q.callback, &q);
    s->spec(q.queue(), id, sp, std::move(t));

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
    std::shared_ptr<rawstor::Session> s = get_next_session();
    std::unique_ptr<ConnectionOpPRead> op =
        std::make_unique<ConnectionOpPRead>(
            *this, s, 0, buf, size, offset, cb, data);
    s->pread(buf, offset, std::move(op));
}


void Connection::preadv(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<rawstor::Session> s = get_next_session();
    std::unique_ptr<ConnectionOpPReadV> op =
        std::make_unique<ConnectionOpPReadV>(
            *this, s, 0, iov, niov, size, offset, cb, data);
    s->preadv(iov, niov, offset, std::move(op));
}


void Connection::pwrite(
    void *buf, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<rawstor::Session> s = get_next_session();
    std::unique_ptr<ConnectionOpPWrite> op =
        std::make_unique<ConnectionOpPWrite>(
            *this, s, 0, buf, size, offset, cb, data);
    s->pwrite(buf, offset, std::move(op));
}


void Connection::pwritev(
    iovec *iov, unsigned int niov, size_t size, off_t offset,
    RawstorCallback *cb, void *data)
{
    std::shared_ptr<rawstor::Session> s = get_next_session();
    std::unique_ptr<ConnectionOpPWriteV> op =
        std::make_unique<ConnectionOpPWriteV>(
            *this, s, 0, iov, niov, size, offset, cb, data);
    s->pwritev(iov, niov, offset, std::move(op));
}


} // rawstor
