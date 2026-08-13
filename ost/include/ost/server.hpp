#ifndef RAWSTOR_OSTBACKEND_SERVER_HPP
#define RAWSTOR_OSTBACKEND_SERVER_HPP

#include <rawstd/uri.hpp>

#include <rawstor/rawio.h>

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawstor {
namespace ostbackend {

class Session;

class Server final {
private:
    RawIOQueue* _queue;
    int _fd;
    std::vector<rawstd::URI> _locations;
    RawIOEvent* _accept_event;
    unsigned int _write_throttle_limit;
    uint64_t _write_backlog_capacity;
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;

    static int _accept(int result, void* data) noexcept;
    int _accept(int result);
    void _add_session(int fd);

public:
    Server(
        unsigned int queue_size, unsigned int write_throttle_limit,
        uint64_t write_backlog_capacity, const std::string& addr,
        unsigned int port, const char* location
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    inline const std::vector<rawstd::URI>& locations() const noexcept {
        return _locations;
    }

    // Per-session cap on writes dispatched to storage without their
    // completion arriving yet -- see Session::_recv_data().
    inline unsigned int write_throttle_limit() const noexcept {
        return _write_throttle_limit;
    }

    // Per-session cap, in bytes, on writes queued behind
    // write_throttle_limit() but not yet dispatched -- see Session::_write().
    inline uint64_t write_backlog_capacity() const noexcept {
        return _write_backlog_capacity;
    }

    void del_session(int fd) noexcept;
    void loop();
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SERVER_HPP
