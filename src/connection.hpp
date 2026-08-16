#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "object.hpp"
#include "telemetry.hpp"

#include <rawstor/rawstor.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>
#include <rawstd/uuid.h>

#include <functional>
#include <list>
#include <memory>
#include <vector>

#include <cstddef>

namespace rawstor {

class Session;

class Connection final {
private:
    struct OpenState;

    rawio::Queue& _queue;
    Object* _object;

    std::vector<std::shared_ptr<Session>> _sessions;
    size_t _session_index;

    /*
     * Expires on close()/destruction; async open/reopen completions check
     * it before touching the connection, which may be gone by then.
     */
    std::shared_ptr<int> _alive;

    /* In-flight session reopens and operations waiting for them. */
    unsigned int _reopens;
    std::vector<std::function<void(int)>> _reopen_waiters;

    static void _open_attempt(const std::shared_ptr<OpenState>& st);
    static void _open_next(const std::shared_ptr<OpenState>& st);
    static void _open_set_object(const std::shared_ptr<OpenState>& st);
    static void _open_failed(const std::shared_ptr<OpenState>& st, int error);

    void _open(
        const rawstd::URI& location, Object* object, size_t nsessions,
        std::function<void(std::vector<std::shared_ptr<Session>>&&, int)>&& cb
    );

    void
    _op(const char* func_name, size_t size, off_t offset,
        const std::shared_ptr<std::function<void(size_t, int)>>& cb,
        const std::shared_ptr<std::function<void(
            std::shared_ptr<Session>, std::function<void(size_t, int)>&&
        )>>& op,
        unsigned int attempt, rawstor::telemetry::TimePoint t_call);

    // Every _op() terminal path -- success, final failure, or a reconnect
    // itself failing -- calls the caller's cb through here exactly once;
    // records the total call-to-cb latency and the top-N sample at that
    // same point, spanning every attempt this logical op took.
    void _finish(
        const char* func_name, size_t size, off_t offset,
        const std::shared_ptr<std::function<void(size_t, int)>>& cb,
        unsigned int attempt, rawstor::telemetry::TimePoint t_call,
        size_t result, int error
    );

public:
    static void list(
        const rawstd::URI& location, unsigned int limit,
        std::vector<RawstdUUID>& uuids, RawstdUUID& token
    );

    static void create(
        rawio::Queue& queue, const rawstd::URI& target,
        const RawstorObjectSpec& sp, std::function<void(int)>&& cb
    );

    static void remove(
        rawio::Queue& queue, const rawstd::URI& target,
        std::function<void(int)>&& cb
    );

    static void spec(
        rawio::Queue& queue, const rawstd::URI& target,
        std::function<void(const RawstorObjectSpec&, int)>&& cb
    );

    static void info(const rawstd::URI& location, RawstorLocationInfo* info);

    explicit Connection(rawio::Queue& queue);
    Connection(const Connection&) = delete;
    ~Connection();

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    void invalidate_session(
        const std::shared_ptr<Session>& s, std::function<void(int)>&& cb
    );

    const rawstd::URI* location() const noexcept;

    void open(
        const rawstd::URI& location, Object* object, size_t nsessions,
        std::function<void(int)>&& cb
    );

    void close();

    void pread(
        void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void preadv(
        iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void pwrite(
        const void* buf, size_t size, off_t offset, bool sync,
        std::function<void(size_t, int)>&& cb
    );

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        bool sync, std::function<void(size_t, int)>&& cb
    );

    void flush(std::function<void(int)>&& cb);
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
