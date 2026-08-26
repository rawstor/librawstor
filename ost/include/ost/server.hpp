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
    bool _owns_fd;
    int _wake_fd;
    bool _stop;
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

    // Only launched when `_wake_fd` is a real fd (see the listen_fd
    // constructor): a single-shot read of one byte from `_wake_fd`, which
    // a caller elsewhere (a signal handler, typically) writes to as a
    // cross-thread "stop" request -- reading it, rather than merely
    // polling for readability, both observes and drains it in one op, so
    // it can never re-fire loop()'s dispatch in a tight spin. Sets _stop
    // and returns once it does; loop() checks _stop after every
    // rawio_wait().
    rawstd::DetachedTask _wake_task();

public:
    // Creates, binds and listens its own socket; closes it in ~Server().
    // `wake_fd`, if not -1, is a readable fd this Server takes ownership
    // of (closes in ~Server()) and treats as a stop request the moment it
    // becomes readable -- see _wake_task().
    Server(
        unsigned int queue_size, const std::string& addr, unsigned int port,
        const char* location, int wake_fd = -1
    );
    // Attaches to `listen_fd`, an already bound+listening socket (typically
    // one returned by bind_listen() and shared by multiple worker threads,
    // each running its own Server on its own RawIOQueue). Does not close
    // `listen_fd` in ~Server() -- ownership stays with the caller, which
    // must keep it open for as long as any Server built from it is alive.
    // `wake_fd` is as above.
    Server(
        unsigned int queue_size, int listen_fd, const char* location,
        int wake_fd = -1
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    // Creates, binds and listens a socket on addr:port (SO_REUSEADDR, then
    // listen(SOMAXCONN)) without wrapping it in a Server. Meant to be
    // called once by a caller that will hand the resulting fd to multiple
    // Server instances (see the listen_fd constructor above); the caller
    // owns the returned fd and must close() it itself once every such
    // Server has been destroyed.
    static int bind_listen(const std::string& addr, unsigned int port);

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

    // Arms the accept_multishot registration (and, if this Server was
    // given a wake_fd, the wake read), then pumps `_queue` until a byte
    // arrives on wake_fd, an interrupting signal is observed directly
    // (best-effort fallback for a Server without a wake_fd), or a genuine
    // error occurs.
    void loop();
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SERVER_HPP
