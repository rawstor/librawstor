#ifndef RAWSTOR_CONNECTION_HPP
#define RAWSTOR_CONNECTION_HPP

#include "object.hpp"

#include <rawstd/uri.hpp>

#include <rawstor/rawstor.h>

#include <functional>
#include <memory>
#include <vector>

#include <cstddef>

namespace rawstor {

class Session;

class Connection final {
private:
    Object* _object;

    std::vector<std::shared_ptr<Session>> _sessions;
    size_t _session_index;

    std::vector<std::shared_ptr<Session>>
    _open(const rawstd::URI& location, Object* object, size_t nsessions);

    void
    _op(const char* func_name, size_t size, off_t offset,
        const std::shared_ptr<std::function<void(size_t, int)>>& cb,
        const std::shared_ptr<std::function<void(
            std::shared_ptr<Session>, std::function<void(size_t, int)>&&
        )>>& op,
        unsigned int attempt);

public:
    Connection();
    Connection(const Connection&) = delete;
    ~Connection();

    Connection& operator=(const Connection&) = delete;

    std::shared_ptr<Session> get_next_session();
    void invalidate_session(const std::shared_ptr<Session>& s);

    const rawstd::URI* location() const noexcept;

    void create(const rawstd::URI& target, const RawstorObjectSpec& sp);

    void remove(const rawstd::URI& target);

    void spec(const rawstd::URI& target, RawstorObjectSpec* sp);

    void open(const rawstd::URI& location, Object* object, size_t nsessions);

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
