#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "object.hpp"

#include <rawstor/rawstor.h>

#include <rawio/queue.hpp>

#include <rawstd/uri.hpp>

#include <functional>
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

    static void _open_attempt(const std::shared_ptr<OpenState>& st);
    static void _open_next(const std::shared_ptr<OpenState>& st);
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
        unsigned int attempt);

public:
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
        const void* buf, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );

    void pwritev(
        const iovec* iov, unsigned int niov, size_t size, off_t offset,
        std::function<void(size_t, int)>&& cb
    );
};

} // namespace rawstor

#endif // RAWSTOR_CONNECTION_HPP
