#include "ost_session.hpp"

#include "object.hpp"
#include "opts.h"
#include "telemetry.hpp"

#include <rawio/queue.hpp>

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/iovec.h>
#include <rawstd/logging.hpp>
#include <rawstd/socket.h>
#include <rawstd/uuid.h>

#include <rawstor/location.h>
#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <arpa/inet.h>

#include <poll.h>

#include <sys/socket.h>

#include <algorithm>
#include <chrono>
#include <iterator>
#include <memory>
#include <stdexcept>
#include <string>
#include <utility>

#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdlib>
#include <cstring>

/**
 * FIXME: iovec should be dynamically allocated at runtime.
 */
#define IOVEC_SIZE 256

namespace {

class SessionOp;

int validate_result(size_t size, size_t result) noexcept {
    if (result == size) {
        return 0;
    }

    rawstd_error("Unexpected event size: %zu != %zu\n", result, size);

    return EAGAIN;
}

int validate_response(const RawstorOSTFrameResponse* response) noexcept {
    assert(response != nullptr);

    if (response->head.magic != RAWSTOR_MAGIC) {
        rawstd_error(
            "Unexpected magic number: %x != %x\n", response->head.magic,
            RAWSTOR_MAGIC
        );
        return EPROTO;
    }

    if (response->body.res < 0) {
        rawstd_error("Server error: %s\n", strerror(-response->body.res));
        return -response->body.res;
    }

    return 0;
}

int validate_cmd(
    RawstorOSTCommandType cmd, RawstorOSTCommandType expected
) noexcept {
    if (cmd == expected) {
        return 0;
    }

    rawstd_error("Unexpected command: %d\n", cmd);
    return EPROTO;
}

int validate_hash(uint64_t hash, uint64_t expected) noexcept {
    if (hash == expected) {
        return 0;
    }

    rawstd_error(
        "Hash mismatch: %llx != %llx\n", (unsigned long long)hash,
        (unsigned long long)expected
    );
    return EPROTO;
}

} // namespace

namespace {

uint64_t hash(const void* buf, size_t size) {
    return rawstd_hash_scalar(buf, size);
}

uint64_t hash(const iovec* iov, unsigned int niov) {
    uint64_t ret;
    int res = rawstd_hash_vector(iov, niov, &ret);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
    return ret;
}

} // namespace

namespace rawstor {
namespace ost {

class SessionOp {
private:
    uint16_t _cid;
    bool _dispatched;

    // telemetry: request_cb() stamps _t_send_done once the request is
    // fully on the wire; _t_created (below, stamped at construction --
    // effectively the moment Connection::_op() dispatched this attempt)
    // to _t_send_done is slat, _t_send_done to the moment a response is
    // ready is rtt, and the _cb() call itself is clat. 0 (never a real
    // timestamp, see telemetry::now()) marks "never sent", so _dispatch()
    // can tell a send that never completed apart from a real zero-length
    // gap.
    rawstor::telemetry::TimePoint _t_send_done;

protected:
    rawstor::telemetry::TimePoint _t_created;

    rawstd::TraceEvent _trace_event;
    // A strong reference, not just a back-pointer: a SessionOp can outlive
    // Session::_ops's own copy of it (e.g. a still-pending send/sendmsg
    // completion keeps a SessionOp alive independently, via its own
    // captured shared_ptr, even after the owning Session is gone from
    // Connection::_sessions and its _ops member has been destroyed). This
    // keeps the Session itself alive for as long as any SessionOp -- in
    // _ops or floating in a pending completion closure -- still needs it.
    std::shared_ptr<rawstor::ost::Session> _session;
    RawstorOSTFrameResponse _response;

    std::function<void(size_t, int)> _cb;

    inline void _dispatch(size_t result, int error) {
        if (_dispatched) {
            // Already delivered -- e.g. Session::_fail_in_flight() forced
            // this op's callback while its own request send was still
            // pending, and that send has now independently completed (with
            // its own success or error). The caller has already been
            // notified once; do not notify it again, and do not touch
            // _session (already removed from its _ops, possibly gone).
            return;
        }
        _dispatched = true;
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight end");

        // rtt/clat only mean something for a request that actually made
        // it onto the wire and got a real response back -- a failed
        // send, a stray cid, or a torn-down session all reach here with
        // an error and nothing useful to measure.
        bool timed = !error && _t_send_done != 0;
        rawstor::telemetry::TimePoint t_response_ready = 0;
        if (timed) {
            t_response_ready = rawstor::telemetry::now();
            rawstor::telemetry::record_rtt(t_response_ready - _t_send_done);
        }

        try {
            _cb(result, error);
        } catch (...) {
            if (timed) {
                rawstor::telemetry::record_clat(
                    rawstor::telemetry::now() - t_response_ready
                );
            }
            _session->_remove_op(_cid);
            throw;
        }

        if (timed) {
            rawstor::telemetry::record_clat(
                rawstor::telemetry::now() - t_response_ready
            );
        }

        _session->_remove_op(_cid);
    }

public:
    SessionOp(
        const std::shared_ptr<rawstor::ost::Session>& session, uint16_t cid,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        _cid(cid),
        _dispatched(false),
        _t_send_done(0),
        _t_created(rawstor::telemetry::now()),
        _trace_event(trace_event),
        _session(session),
        _cb(std::move(cb)) {}

    SessionOp(const SessionOp&) = delete;
    SessionOp(SessionOp&&) = delete;
    virtual ~SessionOp() = default;

    SessionOp& operator=(const SessionOp&) = delete;
    SessionOp& operator=(SessionOp&&) = delete;

    inline uint16_t cid() const noexcept { return _cid; }

    virtual size_t request_size() const noexcept = 0;

    void request_cb(int error) {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "%s\n", "in-flight begin");

        if (!error) {
            _t_send_done = rawstor::telemetry::now();
            rawstor::telemetry::record_slat(_t_send_done - _t_created);
        } else {
            _dispatch(0, error);
        }
    }

    virtual void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) = 0;

    virtual void response_body_cb(const iovec*, unsigned int, size_t, int) {}
};

class SessionOpRead final : public SessionOp {
private:
    void* _buf;
    size_t _size;
    RawstorOSTFrameIO _request;

    uint64_t _hash;

public:
    SessionOpRead(
        const std::shared_ptr<rawstor::ost::Session>& session, uint16_t cid,
        void* buf, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(session, cid, trace_event, std::move(cb)),
        _buf(buf),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .body =
                {
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)_size,
                    .hash = 0,
                    .sync = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_READ);
        }

        if (!error) {
            _hash = response->body.hash;
            *next_head = false;
            *next_size = _size;
        } else {
            _dispatch(0, error);
            *next_head = true;
            *next_size = 0;
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (!error) {
            error = validate_hash(hash(iov, niov), _hash);
        }

        if (result) {
            rawstd_iovec_to_buf(iov, niov, 0, _buf, result);
        }

        _dispatch(result, error);
    }
};

class SessionOpReadV final : public SessionOp {
private:
    iovec* _iov;
    unsigned int _niov;
    size_t _size;
    RawstorOSTFrameIO _request;

    uint64_t _hash;

public:
    SessionOpReadV(
        const std::shared_ptr<rawstor::ost::Session>& session, uint16_t cid,
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(session, cid, trace_event, std::move(cb)),
        _iov(iov),
        _niov(niov),
        _size(size),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_READ,
                    .cid = cid,
                },
            .body =
                {
                    .offset = (uint64_t)offset,
                    .len = (uint32_t)_size,
                    .hash = 0,
                    .sync = 0,
                },
        }),
        _hash(0) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_READ);
        }

        if (!error) {
            _hash = response->body.hash;
            *next_head = false;
            *next_size = _size;
        } else {
            _dispatch(0, error);
            *next_head = true;
            *next_size = 0;
        }
    }

    void response_body_cb(
        const iovec* iov, unsigned int niov, size_t result, int error
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(
            _trace_event, "niov = %u, result = %zu, error = %d\n", niov, result,
            error
        );

        if (!error) {
            error = validate_hash(hash(iov, niov), _hash);
        }

        if (result) {
            rawstd_iovec_to_iovec(iov, niov, 0, _iov, _niov);
        }

        _dispatch(result, error);
    }
};

class SessionOpWrite final : public SessionOp {
private:
    std::vector<iovec> _iov;
    RawstorOSTFrameIO _request;
    msghdr _msg;

public:
    SessionOpWrite(
        const std::shared_ptr<rawstor::ost::Session>& session, uint16_t cid,
        const void* buf, size_t size, off_t offset, bool sync,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(session, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .body = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash(buf, size),
                .sync = sync,
            },
        }) {
        _iov.reserve(2);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        _iov.push_back({
            .iov_base = const_cast<void*>(buf),
            .iov_len = size,
        });
        _msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov.data(),
            .msg_iovlen = static_cast<decltype(_msg.msg_iovlen)>(_iov.size()),
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    }

    const msghdr* request_msg() const noexcept { return &_msg; }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.body.len;
    }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        *next_head = true;
        *next_size = error ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

class SessionOpWriteV final : public SessionOp {
private:
    RawstorOSTFrameIO _request;
    std::vector<iovec> _iov;
    msghdr _msg;

public:
    SessionOpWriteV(
        const std::shared_ptr<rawstor::ost::Session>& session, uint16_t cid,
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync, const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(session, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_WRITE,
                    .cid = cid,
                },
            .body = {
                .offset = (uint64_t)offset,
                .len = (uint32_t)size,
                .hash = hash(iov, niov),
                .sync = sync,
            },
        }) {
        _iov.reserve(1 + niov);
        _iov.push_back({
            .iov_base = &_request,
            .iov_len = sizeof(_request),
        });
        for (unsigned int i = 0; i < niov; ++i) {
            _iov.push_back(iov[i]);
        }
        _msg = {
            .msg_name = nullptr,
            .msg_namelen = 0,
            .msg_iov = _iov.data(),
            .msg_iovlen = static_cast<decltype(_msg.msg_iovlen)>(_iov.size()),
            .msg_control = nullptr,
            .msg_controllen = 0,
            .msg_flags = 0,
        };
    }

    const msghdr* request_msg() const noexcept { return &_msg; }

    size_t request_size() const noexcept override {
        return sizeof(_request) + _request.body.len;
    }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_WRITE);
        }

        _dispatch(
            !error && response != nullptr ? response->body.res : 0, error
        );

        *next_head = true;
        *next_size = error ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

class SessionOpFlush final : public SessionOp {
private:
    RawstorOSTFrameBasic _request;

public:
    SessionOpFlush(
        const std::shared_ptr<rawstor::ost::Session>& session, uint16_t cid,
        const rawstd::TraceEvent& trace_event,
        std::function<void(size_t, int)>&& cb
    ) :
        SessionOp(session, cid, trace_event, std::move(cb)),
        _request({
            .head =
                {
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_FLUSH,
                    .cid = cid,
                },
            .body = {
                .obj_id = {},
                .offset = 0,
                .val = 0,
            },
        }) {}

    const void* request_data() const noexcept { return &_request; }

    size_t request_size() const noexcept override { return sizeof(_request); }

    void response_head_cb(
        const RawstorOSTFrameResponse* response, int error, bool* next_head,
        size_t* next_size
    ) override {
        RAWSTD_TRACE_EVENT_MESSAGE(_trace_event, "error = %d\n", error);

        if (!error) {
            error = validate_response(response);
        }

        if (!error) {
            error = validate_cmd(response->head.cmd, RAWSTOR_CMD_FLUSH);
        }

        _dispatch(0, error);

        *next_head = true;
        *next_size = error ? 0 : sizeof(RawstorOSTFrameResponse);
    }
};

template <typename T = char>
std::vector<T> basic_request(
    int fd, uint16_t cid, RawstorOSTCommandType cmd, const RawstdUUID& id,
    uint64_t val
) {
    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('s', "basic cmd %d\n", cmd);

    bool completed = false;
    RawstorOSTFrameResponse response;
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);

    RawstorOSTFrameBasic request = {
        .head =
            {
                .magic = RAWSTOR_MAGIC,
                .cmd = cmd,
                .cid = cid,
            },
        .body = {
            .obj_id = {},
            .offset = 0,
            .val = val,
        },
    };
    memcpy(request.body.obj_id, id.bytes, sizeof(request.body.obj_id));
    queue->send(
        fd, &request, sizeof(request), RAWSTD_MSG_NOSIGNAL,
        [trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(RawstorOSTFrameBasic), error
            );

            if (!error) {
                error = validate_result(sizeof(RawstorOSTFrameBasic), result);
            }

            if (error) {
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }
        }
    );

    std::vector<T> ret;

    queue->read(
        fd, &response, sizeof(response),
        [&queue, fd, cmd, &response, &completed, trace_event,
         &ret](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                sizeof(response), error
            );

            if (!error) {
                error = validate_result(sizeof(response), result);
            }

            if (!error) {
                error = validate_response(&response);
            }

            if (!error) {
                error = validate_cmd(response.head.cmd, cmd);
            }

            if (error) {
                completed = true;
                RAWSTD_THROW_SYSTEM_ERROR(error);
            }

            if (response.body.res > 0) {
                if (response.body.res % sizeof(T) != 0) {
                    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
                }

                queue->recv_multishot(
                    fd, 1u << 17, 64 * 4, response.body.res, 0,
                    [&completed, &response, trace_event, &ret](
                        const iovec* iov, unsigned int niov, size_t result,
                        int error
                    ) -> size_t {
                        RAWSTD_TRACE_EVENT_MESSAGE(
                            trace_event, "%zu of %zu, error = %d\n", result,
                            response.body.res, error
                        );

                        if (completed) {
                            return 0;
                        }

                        completed = true;

                        if (!error) {
                            error = validate_result(response.body.res, result);
                        }

                        if (result == static_cast<size_t>(response.body.res)) {
                            ret.resize(result / sizeof(T));
                            rawstd_iovec_to_buf(
                                iov, niov, 0, ret.data(), result
                            );
                            error = 0;
                        }

                        if (error) {
                            RAWSTD_THROW_SYSTEM_ERROR(error);
                        }

                        return 0;
                    }
                );
            } else {
                completed = true;
            }
        }
    );

    while (!completed) {
        queue->wait_timeout(rawstor_opts_tcp_user_timeout());
    }

    return ret;
}

void Session::_fail_in_flight(int error, bool* next_head, size_t* next_size) {
    if (!_ops.empty()) {
        // Every op still in _ops needs this, not just the ones whose
        // request has already finished sending: an op between _add_op() and
        // its own request_cb() firing is just as stranded by this session
        // going away, and its pending send is not guaranteed to itself
        // complete with an error (e.g. if the socket is never explicitly
        // closed/cancelled once this session is replaced) -- skipping it
        // here left it waiting forever. SessionOp guards against the
        // resulting double dispatch if that pending send does independently
        // complete afterwards.
        std::vector<std::shared_ptr<SessionOp>> ops;
        ops.reserve(_ops.size());
        for (const auto& i : _ops) {
            ops.push_back(i.second);
        }
        for (const auto& i : ops) {
            i->response_head_cb(nullptr, error, next_head, next_size);
        }
    }
    *next_head = true;
    *next_size = 0;
}

SessionOp* Session::_find_op(uint16_t cid) {
    auto it = _ops.find(cid);
    if (it == _ops.end()) {
        return nullptr;
    }

    return it->second.get();
}

void Session::_add_op(const std::shared_ptr<SessionOp>& op) {
    _ops[op->cid()] = op;
    rawstor::telemetry::op_started();
}

void Session::_remove_op(uint16_t cid) {
    _ops.erase(cid);
    rawstor::telemetry::op_finished();
}

Session::Session(Private p, rawio::Queue& queue, const rawstd::URI& location) :
    rawstor::Session(p, queue, location),
    _cid_counter(0),
    _read_event(nullptr) {
    int fd = _connect();
    set_fd(fd);
}

Session::~Session() {
    if (_read_event != nullptr) {
        try {
            _queue.cancel(_read_event);
        } catch (const std::exception& e) {
            rawstd_warning("Failed to cancel event: %s\n", e.what());
        }
        _read_event = nullptr;
    }
}

int Session::_connect() {
    if (!location().path().str().empty() && location().path().str() != "/") {
        rawstd_error("Empty path expected: %s\n", location().str().c_str());
        RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
    }

    int res;

    int fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd == -1) {
        RAWSTD_THROW_ERRNO();
    }

    try {
        res = rawstd_socket_set_nosigpipe(fd);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        unsigned int so_sndtimeo = rawstor_opts_so_sndtimeo();
        if (so_sndtimeo != 0) {
            res = rawstd_socket_set_snd_timeout(fd, so_sndtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int so_rcvtimeo = rawstor_opts_so_rcvtimeo();
        if (so_rcvtimeo != 0) {
            res = rawstd_socket_set_rcv_timeout(fd, so_rcvtimeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        unsigned int tcp_user_timeo = rawstor_opts_tcp_user_timeout();
        if (tcp_user_timeo != 0) {
            res = rawstd_socket_set_user_timeout(fd, tcp_user_timeo);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        }

        sockaddr_in servaddr = {};
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(location().port());

        res = inet_pton(
            AF_INET, location().hostname().c_str(), &servaddr.sin_addr
        );
        if (res == 0) {
            RAWSTD_THROW_SYSTEM_ERROR(EINVAL);
        } else if (res == -1) {
            RAWSTD_THROW_ERRNO();
        }

        rawstd_info(
            "fd %d: Connecting to %s...\n", fd, location().str().c_str()
        );
        int res = connect(fd, (sockaddr*)&servaddr, sizeof(servaddr));
        if (res == -1) {
            if (errno == EINTR) {
                errno = 0;

                pollfd fds = {
                    .fd = fd,
                    .events = POLLOUT,
                    .revents = 0,
                };
                rawstd_warning("Connect interrupted; polling...\n");
                for (unsigned int attempt = 1;
                     attempt <= rawstor_opts_io_attempts(); ++attempt) {
                    try {
                        res = poll(&fds, 1, so_sndtimeo);
                        if (res == -1) {
                            RAWSTD_THROW_ERRNO();
                        }
                        if (res == 0) {
                            RAWSTD_THROW_SYSTEM_ERROR(ETIMEDOUT);
                        }
                        break;
                    } catch (const std::exception& e) {
                        if (attempt != rawstor_opts_io_attempts()) {
                            rawstd_warning(
                                "Poll failed; error: %s; "
                                "attempt: %d of %d; retrying...\n",
                                e.what(), attempt, rawstor_opts_io_attempts()
                            );
                        } else {
                            rawstd_warning(
                                "Poll failed; error: %s; "
                                "attempt: %d of %d; failing...\n",
                                e.what(), attempt, rawstor_opts_io_attempts()
                            );
                            throw;
                        }
                    }
                }

                int value = 0;
                socklen_t value_len = sizeof(value);
                res = getsockopt(fd, SOL_SOCKET, SO_ERROR, &value, &value_len);
                if (res == -1) {
                    RAWSTD_THROW_ERRNO();
                }
                if (value) {
                    RAWSTD_THROW_SYSTEM_ERROR(value);
                }

                if (!(fds.revents & POLLOUT)) {
                    RAWSTD_THROW_SYSTEM_ERROR(ENOTCONN);
                }
            } else {
                RAWSTD_THROW_ERRNO();
            }
        }
        rawstd_info("fd %d: Connected\n", fd);

        rawio::Queue::setup_fd(fd);
    } catch (...) {
        ::close(fd);
        rawstd_info("fd %d: Closed\n", fd);
        throw;
    }

    return fd;
}

void Session::_set_object(Object* object) {
    basic_request(
        fd(), _cid_counter++, RAWSTOR_CMD_SET_OBJECT, object->id(), 0
    );
}

void Session::list(
    unsigned int limit, const RawstdUUID& token,
    std::function<void(std::vector<RawstdUUID>&&, const RawstdUUID&, int)>&& cb
) {
    int error = 0;
    std::vector<RawstdUUID> uuids;
    try {
        uuids = basic_request<RawstdUUID>(
            fd(), _cid_counter++, RAWSTOR_CMD_LIST, token, limit
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    } catch (...) {
        error = EIO;
    }
    RawstdUUID next_token = {};
    if (!uuids.empty()) {
        next_token = uuids.back();
        uuids.resize(uuids.size() - 1);
    }
    cb(std::move(uuids), next_token, error);
}

void Session::create(
    const RawstdUUID& id, const RawstorObjectSpec& spec,
    std::function<void(int)>&& cb
) {
    int error = 0;
    try {
        basic_request(
            fd(), _cid_counter++, RAWSTOR_CMD_ALLOCATE, id, spec.size
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    } catch (...) {
        error = EIO;
    }
    cb(error);
}

void Session::remove(const RawstdUUID& id, std::function<void(int)>&& cb) {
    int error = 0;
    try {
        basic_request(fd(), _cid_counter++, RAWSTOR_CMD_RELEASE, id, 0);
    } catch (const std::system_error& e) {
        error = e.code().value();
    } catch (...) {
        error = EIO;
    }
    cb(error);
}

void Session::spec(
    const RawstdUUID& id,
    std::function<void(const RawstorObjectSpec&, int)>&& cb
) {
    rawstd_info("%s: Reading object specification...\n", str().c_str());

    int error = 0;
    RawstorObjectSpec ret = {};
    try {
        std::vector<char> response =
            basic_request(fd(), _cid_counter++, RAWSTOR_CMD_SPEC, id, 0);
        if (response.size() != sizeof(ret)) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        ret = *static_cast<RawstorObjectSpec*>(
            static_cast<void*>(response.data())
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    } catch (...) {
        error = EIO;
    }

    if (!error) {
        rawstd_info(
            "%s: Object specification successfully received\n", str().c_str()
        );
    }

    cb(ret, error);
}

void Session::info(std::function<void(const RawstorLocationInfo&, int)>&& cb) {
    rawstd_info("%s: Reading location info...\n", str().c_str());

    int error = 0;
    RawstorLocationInfo ret = {};
    try {
        RawstdUUID unused_id = {};
        std::vector<char> response = basic_request(
            fd(), _cid_counter++, RAWSTOR_CMD_LOCATION_INFO, unused_id, 0
        );
        if (response.size() != sizeof(ret)) {
            RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
        }
        ret = *static_cast<RawstorLocationInfo*>(
            static_cast<void*>(response.data())
        );
    } catch (const std::system_error& e) {
        error = e.code().value();
    } catch (...) {
        error = EIO;
    }

    if (!error) {
        rawstd_info("%s: Location info successfully received\n", str().c_str());
    }

    cb(ret, error);
}

void Session::set_object(Object* object) {
    assert(_read_event == nullptr);

    _set_object(object);

    rawstd::TraceEvent trace_event =
        RAWSTD_TRACE_EVENT('m', "%s\n", "multishot recv");
    _read_event = _queue.recv_multishot(
        fd(), 1u << 17, 64 * 4, sizeof(RawstorOSTFrameResponse), 0,
        [weak = std::weak_ptr<rawstor::ost::Session>(
             std::static_pointer_cast<rawstor::ost::Session>(shared_from_this())
         ),
         cid = 0, is_head = true, size = sizeof(RawstorOSTFrameResponse),
         trace_event](
            const iovec* iov, unsigned int niov, size_t result, int error
        ) mutable -> size_t {
            if (error == ECANCELED) {
                return 0;
            }

            // A strong self-reference here (instead of weak_ptr::lock())
            // would keep this Session alive purely because its own recv
            // registration exists -- including while this very lambda's
            // captured shared_ptr is what's being torn down as part of
            // the *owning* rawio::Queue's own destruction (e.g. process
            // shutdown), which would then call back into that same,
            // still-destructing Queue via ~Session()'s _queue.cancel(),
            // a reentrant heap-use-after-free. A missing session here
            // means it was already destroyed via some other, unrelated
            // reference dropping -- nothing to do.
            std::shared_ptr<rawstor::ost::Session> session = weak.lock();
            if (session == nullptr) {
                return 0;
            }

            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result, size, error
            );

            if (!error) {
                error = validate_result(size, result);
            }

            if (!error) {
                try {
                    if (is_head) {
                        RawstorOSTFrameResponse response;
                        rawstd_iovec_to_buf(
                            iov, niov, 0, &response, sizeof(response)
                        );
                        cid = response.head.cid;
                        SessionOp* op = session->_find_op(cid);
                        if (op == nullptr) {
                            // A stray/late response for an op this
                            // connection already failed and that
                            // Connection::_op() has since retried on a
                            // different session. Not a live op's callback
                            // throwing, so fail whatever is still in
                            // flight and stop -- do not propagate, that
                            // would tear down the whole rawio::Queue
                            // instead of just this connection.
                            rawstd_error("Unexpected cid: %u\n", cid);
                            session->_fail_in_flight(EPROTO, &is_head, &size);
                            return size;
                        }
                        op->response_head_cb(&response, 0, &is_head, &size);
                    } else {
                        SessionOp* op = session->_find_op(cid);
                        if (op == nullptr) {
                            rawstd_error("Unexpected cid: %u\n", cid);
                            session->_fail_in_flight(EPROTO, &is_head, &size);
                            return size;
                        }
                        op->response_body_cb(iov, niov, result, error);
                        is_head = true;
                        size = sizeof(RawstorOSTFrameResponse);
                    }
                } catch (const std::system_error& e) {
                    error = e.code().value();
                    session->_fail_in_flight(error, &is_head, &size);
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                } catch (const std::exception& e) {
                    rawstd_error("%s\n", e.what());
                    error = EPROTO;
                    session->_fail_in_flight(error, &is_head, &size);
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                }
            }

            if (error) {
                session->_fail_in_flight(error, &is_head, &size);
            }

            return size;
        }
    );
}

void Session::pread(
    void* buf, size_t size, off_t offset, std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpRead> op = std::make_shared<SessionOpRead>(
        std::static_pointer_cast<Session>(shared_from_this()), _cid_counter++,
        buf, size, offset, trace_event, std::move(cb)
    );
    _add_op(op);

    _queue.send(
        fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL,
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(op->request_size(), result);
            }

            op->request_cb(error);
        }
    );
}

void Session::preadv(
    iovec* iov, unsigned int niov, size_t size, off_t offset,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd\n", fd(), size, (intmax_t)offset
    );

    std::shared_ptr<SessionOpReadV> op = std::make_shared<SessionOpReadV>(
        std::static_pointer_cast<Session>(shared_from_this()), _cid_counter++,
        iov, niov, size, offset, trace_event, std::move(cb)
    );
    _add_op(op);

    _queue.send(
        fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL,
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(op->request_size(), result);
            }

            op->request_cb(error);
        }
    );
}

void Session::pwrite(
    const void* buf, size_t size, off_t offset, bool sync,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd, sync = %d\n", fd(), size,
        (intmax_t)offset, sync
    );

    std::shared_ptr<SessionOpWrite> op = std::make_shared<SessionOpWrite>(
        std::static_pointer_cast<Session>(shared_from_this()), _cid_counter++,
        buf, size, offset, sync, trace_event, std::move(cb)
    );
    _add_op(op);

    _queue.sendmsg(
        fd(), op->request_msg(), RAWSTD_MSG_NOSIGNAL,
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(op->request_size(), result);
            }

            op->request_cb(error);
        }
    );
}

void Session::pwritev(
    const iovec* iov, unsigned int niov, size_t size, off_t offset, bool sync,
    std::function<void(size_t, int)>&& cb
) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT(
        's', "fd = %d, size = %zu, offset = %jd, sync = %d\n", fd(), size,
        (intmax_t)offset, sync
    );

    std::shared_ptr<SessionOpWriteV> op = std::make_shared<SessionOpWriteV>(
        std::static_pointer_cast<Session>(shared_from_this()), _cid_counter++,
        iov, niov, size, offset, sync, trace_event, std::move(cb)
    );
    _add_op(op);

    _queue.sendmsg(
        fd(), op->request_msg(), RAWSTD_MSG_NOSIGNAL,
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(op->request_size(), result);
            }

            op->request_cb(error);
        }
    );
}

void Session::flush(std::function<void(int)>&& cb) {
    rawstd::TraceEvent trace_event = RAWSTD_TRACE_EVENT('s', "fd = %d\n", fd());

    std::shared_ptr<SessionOpFlush> op = std::make_shared<SessionOpFlush>(
        std::static_pointer_cast<Session>(shared_from_this()), _cid_counter++,
        trace_event, [cb = std::move(cb)](size_t, int error) { cb(error); }
    );
    _add_op(op);

    _queue.send(
        fd(), op->request_data(), op->request_size(), RAWSTD_MSG_NOSIGNAL,
        [op, trace_event](size_t result, int error) {
            RAWSTD_TRACE_EVENT_MESSAGE(
                trace_event, "%zu of %zu, error = %d\n", result,
                op->request_size(), error
            );

            if (!error) {
                error = validate_result(op->request_size(), result);
            }

            op->request_cb(error);
        }
    );
}

} // namespace ost
} // namespace rawstor
