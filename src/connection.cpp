#include "connection.hpp"

#include "opts.h"
#include "session.hpp"
#include "task.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/iovec.h>

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
class Queue final {
private:
    unsigned int _operations;
    std::unique_ptr<rawstor::io::Queue> _q;

public:
    Queue(unsigned int operations, unsigned int depth) :
        _operations(operations),
        _q(rawstor::io::Queue::create(depth)) {}

    Queue(const Queue&) = delete;

    Queue& operator=(const Queue&) = delete;

    inline void sub_operation() noexcept { --_operations; }

    inline rawstor::io::Queue& queue() noexcept { return *_q; }

    void wait() {
        while (_operations > 0) {
            _q->wait(rawstor_opts_wait_timeout());
        }
    }
};

/**
 * TODO: Remove this class.
 */
class QueueTask final : public rawstor::Task {
private:
    Queue& _q;

public:
    QueueTask(Queue& q) : _q(q) {}

    void operator()(RawstorObject*, size_t, int error) override {
        _q.sub_operation();

        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }
    }
};

class ConnectionOpScalar : public rawstor::Task {
protected:
    rawstor::Connection& _cn;
    std::shared_ptr<rawstor::Session> _s;
    unsigned int _attempt;

    std::unique_ptr<rawstor::Task> _t;

    virtual void _retry(const std::shared_ptr<rawstor::Session>& s) = 0;

public:
    ConnectionOpScalar(
        rawstor::Connection& cn, const std::shared_ptr<rawstor::Session>& s,
        unsigned int attempt, std::unique_ptr<rawstor::Task> t
    ) :
        _cn(cn),
        _s(s),
        _attempt(attempt),
        _t(std::move(t)) {}

    void operator()(RawstorObject* o, size_t result, int error) override {
        if (!error) {
            if (_attempt > 0) {
                rawstor_warning(
                    "%s; success on %s; attempt: %d of %d\n", str().c_str(),
                    _s->str().c_str(), _attempt + 1, rawstor_opts_io_attempts()
                );
            }
            (*_t)(o, result, error);
            return;
        }

        if (_attempt + 1 >= rawstor_opts_io_attempts()) {
            rawstor_error(
                "%s; error on %s: %s; attempt %d of %d; "
                "failing...\n",
                str().c_str(), _s->str().c_str(), std::strerror(error),
                _attempt + 1, rawstor_opts_io_attempts()
            );
            (*_t)(o, result, error);
            return;
        }

        rawstor_warning(
            "%s; error on %s: %s; attempt: %d of %d; "
            "retrying...\n",
            str().c_str(), _s->str().c_str(), std::strerror(error),
            _attempt + 1, rawstor_opts_io_attempts()
        );

        try {
            _cn.invalidate_session(_s);
            _retry(_cn.get_next_session());
        } catch (const std::system_error& e) {
            (*_t)(o, result, e.code().value());
        } catch (const std::exception& e) {
            rawstor_error(
                "%s; exception on %s: %s; attempt %d of %d; "
                "failing...\n",
                str().c_str(), _s->str().c_str(), e.what(), _attempt + 1,
                rawstor_opts_io_attempts()
            );
            (*_t)(o, result, EIO);
        }
    }

    virtual std::string str() const = 0;
};

class ConnectionOpVector : public rawstor::Task {
protected:
    rawstor::Connection& _cn;
    std::shared_ptr<rawstor::Session> _s;
    unsigned int _attempt;

    std::unique_ptr<rawstor::Task> _t;

    virtual void _retry(const std::shared_ptr<rawstor::Session>& s) = 0;

public:
    ConnectionOpVector(
        rawstor::Connection& cn, const std::shared_ptr<rawstor::Session>& s,
        unsigned int attempt, std::unique_ptr<rawstor::Task> t
    ) :
        _cn(cn),
        _s(s),
        _attempt(attempt),
        _t(std::move(t)) {}

    void operator()(RawstorObject* o, size_t result, int error) override {
        if (!error) {
            if (_attempt > 0) {
                rawstor_warning(
                    "%s; success on %s; attempt: %d of %d\n", str().c_str(),
                    _s->str().c_str(), _attempt + 1, rawstor_opts_io_attempts()
                );
            }
            (*_t)(o, result, error);
            return;
        }

        if (_attempt + 1 >= rawstor_opts_io_attempts()) {
            rawstor_error(
                "%s; error on %s: %s; attempt %d of %d; "
                "failing...\n",
                str().c_str(), _s->str().c_str(), std::strerror(error),
                _attempt + 1, rawstor_opts_io_attempts()
            );
            (*_t)(o, result, error);
            return;
        }

        rawstor_warning(
            "%s; error on %s: %s; attempt: %d of %d; "
            "retrying...\n",
            str().c_str(), _s->str().c_str(), std::strerror(error),
            _attempt + 1, rawstor_opts_io_attempts()
        );

        try {
            _cn.invalidate_session(_s);
            _retry(_cn.get_next_session());
        } catch (const std::system_error& e) {
            (*_t)(o, result, e.code().value());
        } catch (const std::exception& e) {
            rawstor_error(
                "%s; exception on %s: %s; attempt %d of %d; "
                "failing...\n",
                str().c_str(), _s->str().c_str(), e.what(), _attempt + 1,
                rawstor_opts_io_attempts()
            );
            (*_t)(o, result, EIO);
        }
    }

    virtual std::string str() const = 0;
};

class ConnectionOpPRead final : public ConnectionOpScalar {
protected:
    void* _buf;
    size_t _size;
    off_t _offset;

    void _retry(const std::shared_ptr<rawstor::Session>& s) override {
        std::unique_ptr<rawstor::Task> op = std::make_unique<ConnectionOpPRead>(
            _cn, s, _attempt + 1, _buf, _size, _offset, std::move(_t)
        );
        s->pread(_buf, _size, _offset, std::move(op));
    }

public:
    ConnectionOpPRead(
        rawstor::Connection& cn, const std::shared_ptr<rawstor::Session>& s,
        unsigned int attempt, void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::Task> t
    ) :
        ConnectionOpScalar(cn, s, attempt, std::move(t)),
        _buf(buf),
        _size(size),
        _offset(offset) {}

    std::string str() const override {
        std::ostringstream oss;
        oss << "IO pread: size = " << _size << ", offset = " << _offset;
        return oss.str();
    }
};

class ConnectionOpPReadV final : public ConnectionOpVector {
protected:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;
    off_t _offset;

    void _retry(const std::shared_ptr<rawstor::Session>& s) override {
        std::unique_ptr<rawstor::Task> op =
            std::make_unique<ConnectionOpPReadV>(
                _cn, s, _attempt + 1, _iov, _niov, _size, _offset, std::move(_t)
            );
        s->preadv(_iov, _niov, _size, _offset, std::move(op));
    }

public:
    ConnectionOpPReadV(
        rawstor::Connection& cn, const std::shared_ptr<rawstor::Session>& s,
        unsigned int attempt, iovec* iov, unsigned int niov, size_t size,
        off_t offset, std::unique_ptr<rawstor::Task> t
    ) :
        ConnectionOpVector(cn, s, attempt, std::move(t)),
        _iov(iov),
        _niov(niov),
        _size(size),
        _offset(offset) {}

    std::string str() const override {
        std::ostringstream oss;
        oss << "IO preadv: size = " << _size << ", offset = " << _offset;
        return oss.str();
    }
};

class ConnectionOpPWrite final : public ConnectionOpScalar {
protected:
    const void* _buf;
    size_t _size;
    off_t _offset;

    void _retry(const std::shared_ptr<rawstor::Session>& s) override {
        std::unique_ptr<rawstor::Task> op =
            std::make_unique<ConnectionOpPWrite>(
                _cn, s, _attempt + 1, _buf, _size, _offset, std::move(_t)
            );
        s->pwrite(_buf, _size, _offset, std::move(op));
    }

public:
    ConnectionOpPWrite(
        rawstor::Connection& cn, const std::shared_ptr<rawstor::Session>& s,
        unsigned int attempt, const void* buf, size_t size, off_t offset,
        std::unique_ptr<rawstor::Task> t
    ) :
        ConnectionOpScalar(cn, s, attempt, std::move(t)),
        _buf(buf),
        _size(size),
        _offset(offset) {}

    std::string str() const override {
        std::ostringstream oss;
        oss << "IO pwrite: size = " << _size << ", offset = " << _offset;
        return oss.str();
    }
};

class ConnectionOpPWriteV final : public ConnectionOpVector {
private:
    const iovec* _iov;
    unsigned int _niov;
    size_t _size;
    off_t _offset;

    void _retry(const std::shared_ptr<rawstor::Session>& s) override {
        std::unique_ptr<rawstor::Task> op =
            std::make_unique<ConnectionOpPWriteV>(
                _cn, s, _attempt + 1, _iov, _niov, _size, _offset, std::move(_t)
            );
        s->pwritev(_iov, _niov, _size, _offset, std::move(op));
    }

public:
    ConnectionOpPWriteV(
        rawstor::Connection& cn, const std::shared_ptr<rawstor::Session>& s,
        unsigned int attempt, const iovec* iov, unsigned int niov, size_t size,
        off_t offset, std::unique_ptr<rawstor::Task> t
    ) :
        ConnectionOpVector(cn, s, attempt, std::move(t)),
        _iov(iov),
        _niov(niov),
        _size(size),
        _offset(offset) {}

    std::string str() const override {
        std::ostringstream oss;
        oss << "IO pwritev: size = " << _size << ", offset = " << _offset;
        return oss.str();
    }
};

} // namespace

namespace rawstor {

Connection::Connection(unsigned int depth) :
    _object(nullptr),
    _depth(depth),
    _session_index(0) {
}

Connection::~Connection() {
    try {
        close();
    } catch (const std::system_error& e) {
        rawstor_error("Connection::close(): %s\n", e.what());
    }
}

std::vector<std::shared_ptr<Session>>
Connection::_open(const URI& uri, RawstorObject* object, size_t nsessions) {
    std::vector<std::shared_ptr<Session>> sessions;

    for (unsigned int attempt = 1; attempt <= rawstor_opts_io_attempts();
         ++attempt) {
        try {
            Queue q(nsessions, _depth);

            sessions.clear();
            sessions.reserve(nsessions);
            for (size_t i = 0; i < nsessions; ++i) {
                sessions.push_back(Session::create(uri, _depth));
            }

            for (std::shared_ptr<Session> s : sessions) {
                std::unique_ptr<QueueTask> t = std::make_unique<QueueTask>(q);
                s->set_object(q.queue(), object, std::move(t));
            }

            q.wait();

            break;
        } catch (const std::system_error& e) {
            if (attempt != rawstor_opts_io_attempts()) {
                rawstor_warning(
                    "Open session failed; error: %s; "
                    "attempt: %d of %d; retrying...\n",
                    e.what(), attempt, rawstor_opts_io_attempts()
                );
            } else {
                rawstor_warning(
                    "Open session failed; error: %s; "
                    "attempt: %d of %d; failing...\n",
                    e.what(), attempt, rawstor_opts_io_attempts()
                );
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

void Connection::invalidate_session(const std::shared_ptr<Session>& s) {
    typename std::vector<std::shared_ptr<Session>>::iterator it =
        std::find(_sessions.begin(), _sessions.end(), s);

    if (it != _sessions.end()) {
        _sessions.erase(it);

        std::vector<std::shared_ptr<Session>> new_sessions =
            _open(s->uri(), _object, 1);

        _sessions.push_back(new_sessions.front());
    }
}

const URI* Connection::uri() const noexcept {
    if (_sessions.empty()) {
        return nullptr;
    }

    return &_sessions.front()->uri();
}

void Connection::create(const URI& uri, const RawstorObjectSpec& sp) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s = Session::create(uri.parent(), _depth);
    std::unique_ptr<QueueTask> t = std::make_unique<QueueTask>(q);
    s->create(q.queue(), id, sp, std::move(t));

    q.wait();
}

void Connection::remove(const URI& uri) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s = Session::create(uri.parent(), _depth);
    std::unique_ptr<QueueTask> t = std::make_unique<QueueTask>(q);
    s->remove(q.queue(), id, std::move(t));

    q.wait();
}

void Connection::spec(const URI& uri, RawstorObjectSpec* sp) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s = Session::create(uri.parent(), _depth);
    std::unique_ptr<QueueTask> t = std::make_unique<QueueTask>(q);
    s->spec(q.queue(), id, sp, std::move(t));

    q.wait();
}

void Connection::open(const URI& uri, RawstorObject* object, size_t nsessions) {
    _sessions = _open(uri, object, nsessions);
    _object = object;
}

void Connection::close() {
    _sessions.clear();
    _object = nullptr;
}

void Connection::pread(
    void* buf, size_t size, off_t offset, std::unique_ptr<Task> t
) {
    std::shared_ptr<Session> s = get_next_session();
    std::unique_ptr<Task> op = std::make_unique<ConnectionOpPRead>(
        *this, s, 0, buf, size, offset, std::move(t)
    );
    s->pread(buf, size, offset, std::move(op));
}

void Connection::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<Task> t
) {
    std::shared_ptr<Session> s = get_next_session();
    std::unique_ptr<Task> op = std::make_unique<ConnectionOpPReadV>(
        *this, s, 0, iov, niov, size, offset, std::move(t)
    );
    s->preadv(iov, niov, size, offset, std::move(op));
}

void Connection::pwrite(
    const void* buf, size_t size, off_t offset, std::unique_ptr<Task> t
) {
    std::shared_ptr<Session> s = get_next_session();
    std::unique_ptr<Task> op = std::make_unique<ConnectionOpPWrite>(
        *this, s, 0, buf, size, offset, std::move(t)
    );
    s->pwrite(buf, size, offset, std::move(op));
}

void Connection::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::unique_ptr<Task> t
) {
    std::shared_ptr<Session> s = get_next_session();
    std::unique_ptr<Task> op = std::make_unique<ConnectionOpPWriteV>(
        *this, s, 0, iov, niov, size, offset, std::move(t)
    );
    s->pwritev(iov, niov, size, offset, std::move(op));
}

} // namespace rawstor
