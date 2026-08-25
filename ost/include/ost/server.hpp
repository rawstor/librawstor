#ifndef RAWSTOR_OSTBACKEND_SERVER_HPP
#define RAWSTOR_OSTBACKEND_SERVER_HPP

#include <rawstd/coro.hpp>
#include <rawstd/uri.hpp>

#include <rawstor/rawio.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawstor {
namespace ostbackend {

class Client;

class Server final {
private:
    RawIOQueue* _queue;
    int _fd;
    std::vector<rawstd::URI> _locations;
    RawIOEvent* _accept_event;
    std::unordered_map<int, std::shared_ptr<Client>> _clients;

    // Drives the accept_multishot registration for this Server's whole
    // lifetime: co_awaits a CallbackStream<int>'s next() in a loop,
    // handing each accepted fd to _add_client(). Ends (and frees its own
    // coroutine frame, being a DetachedTask) once the stream throws --
    // either ~Server()'s rawio_cancel(), or a genuine error on the
    // listening socket.
    rawstd::DetachedTask _accept_task();
    rawstd::Task<void> _add_client(int fd);

public:
    Server(
        unsigned int queue_size, const std::string& addr, unsigned int port,
        const char* location
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    inline const std::vector<rawstd::URI>& locations() const noexcept {
        return _locations;
    }

    // Drops `fd`'s Client from this Server (if it still has one) and, if
    // that was the last reference to it (see the .cpp for why that check
    // matters), asynchronously closes it via Client::close(). Callers
    // that can't be coroutines themselves (most of today's -- a plain
    // callback, or a catch block, where co_await isn't allowed) launch
    // this via a small local DetachedTask wrapper instead of co_awaiting
    // it directly; see ost/src/client.cpp's own del_client()-launching
    // helper for that shape.
    rawstd::Task<void> del_client(int fd);

    // Arms the accept_multishot registration, then pumps `_queue` until
    // interrupted or a genuine error occurs.
    void loop();
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SERVER_HPP
