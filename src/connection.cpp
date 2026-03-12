#include "connection.hpp"

#include "opts.h"
#include "rawstor_internals.hpp"
#include "session.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/iovec.h>
#include <rawstorstd/logging.hpp>

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
            sessions.clear();
            sessions.reserve(nsessions);
            for (size_t i = 0; i < nsessions; ++i) {
                sessions.push_back(Session::create(*io_queue, uri, _depth));
            }

            for (std::shared_ptr<Session> s : sessions) {
                s->set_object(object);
            }

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

void Connection::_op(
    const char* func_name, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb,
    const std::shared_ptr<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>&
        op,
    unsigned int attempt
) {
    rawstor::TraceEvent trace_event = RAWSTOR_TRACE_EVENT(
        'c', "%s(): size = %zu, offset = %jd\n", func_name, size,
        (intmax_t)offset
    );

    std::shared_ptr<Session> s = get_next_session();
    (*op)(
        s, [this, s, func_name, size, offset, cb = std::move(cb), op, attempt,
            trace_event](size_t result, int error) mutable {
            RAWSTOR_TRACE_EVENT_MESSAGE(
                trace_event, "result = %zu, error = %d\n", result, error
            );

            if (!error) {
                if (attempt > 0) {
                    rawstor_warning(
                        "IO %s: size = %zu, offset = %jd; "
                        "success on %s; "
                        "attempt: %d of %d\n",
                        func_name, size, (intmax_t)offset, s->str().c_str(),
                        attempt + 1, rawstor_opts_io_attempts()
                    );
                }
                cb(result, error);
                return;
            }

            if (attempt + 1 >= rawstor_opts_io_attempts()) {
                rawstor_error(
                    "IO %s: size = %zu, offset = %jd; "
                    "error on %s: %s; "
                    "attempt %d of %d; failing...\n",
                    func_name, size, (intmax_t)offset, s->str().c_str(),
                    std::strerror(error), attempt + 1,
                    rawstor_opts_io_attempts()
                );
                cb(result, error);
                return;
            }

            rawstor_warning(
                "IO %s: size = %zu, offset = %jd; "
                "error on %s: %s; "
                "attempt: %d of %d; retrying...\n",
                func_name, size, (intmax_t)offset, s->str().c_str(),
                std::strerror(error), attempt + 1, rawstor_opts_io_attempts()
            );

            try {
                invalidate_session(s);
            } catch (const std::system_error& e) {
                cb(result, e.code().value());
                return;
            } catch (const std::exception& e) {
                rawstor_error(
                    "IO %s: size = %zu, offset = %jd; "
                    "exception on %s: %s; "
                    "attempt %d of %d; failing...\n",
                    func_name, size, (intmax_t)offset, s->str().c_str(),
                    e.what(), attempt + 1, rawstor_opts_io_attempts()
                );
                cb(result, EIO);
                return;
            }

            _op(func_name, size, offset, std::move(cb), op, attempt + 1);
        }
    );
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

    std::unique_ptr<Session> s =
        Session::create(q.queue(), uri.parent(), _depth);
    s->create(id, sp, [&q](int error) {
        q.sub_operation();

        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }
    });

    q.wait();
}

void Connection::remove(const URI& uri) {
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s =
        Session::create(q.queue(), uri.parent(), _depth);
    s->remove(id, [&q](int error) {
        q.sub_operation();

        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }
    });

    q.wait();
}

void Connection::spec(const URI& uri, RawstorObjectSpec* sp) {
    rawstor_info("Connection::spec()\n");
    RawstorUUID id;
    int res = rawstor_uuid_from_string(&id, uri.path().filename().c_str());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }

    Queue q(1, _depth);

    std::unique_ptr<Session> s =
        Session::create(q.queue(), uri.parent(), _depth);
    s->spec(id, [&q, sp](const RawstorObjectSpec& spec, int error) {
        q.sub_operation();

        if (error) {
            RAWSTOR_THROW_SYSTEM_ERROR(error);
        }

        *sp = spec;
    });

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
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    auto op = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [buf, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pread(buf, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, std::move(cb), op, 0);
}

void Connection::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    auto op = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [iov, niov, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->preadv(iov, niov, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, std::move(cb), op, 0);
}

void Connection::pwrite(
    const void* buf, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    auto op = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [buf, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pwrite(buf, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, std::move(cb), op, 0);
}

void Connection::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    auto op = std::make_shared<std::function<
        void(std::shared_ptr<Session>, std::function<void(size_t, int)>&&)>>(
        [iov, niov, size, offset](
            std::shared_ptr<Session> s, std::function<void(size_t, int)>&& cb
        ) { s->pwritev(iov, niov, size, offset, std::move(cb)); }
    );
    _op(__FUNCTION__, size, offset, std::move(cb), op, 0);
}

} // namespace rawstor
