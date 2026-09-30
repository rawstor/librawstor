#ifndef RAWSTOR_MDS_SERVER_HPP
#define RAWSTOR_MDS_SERVER_HPP

#include "store.hpp"

#include <rawstd/coro.hpp>

#include <rawstor/rawio.h>

#include <memory>
#include <string>
#include <unordered_map>

namespace rawstor {
namespace mds {

class Client;

// One MDS worker (docs/mds.md, "MDS server, v1"): its own RawIOQueue and
// clients, accepting on a listening socket it may share with other
// workers' Servers -- same shape as ostserver::Server, each worker thread
// registering its own accept_multishot on that one fd. Every worker shares
// one ObjectStore (thread-safe, see its own doc comment); its calls are
// synchronous and rare, so a briefly blocked event loop is accepted.
class Server final {
private:
    RawIOQueue* _queue;
    int _fd;
    int _wake_fd;
    bool _stop;
    ObjectStore& _store;
    RawIOEvent* _accept_event;
    std::unordered_map<int, std::shared_ptr<Client>> _clients;

    rawstd::DetachedTask _accept_task();
    rawstd::Task<void> _add_client(int fd);

    // Only launched when `wake_fd` (the constructor's last argument) holds
    // a real fd -- same self-pipe shutdown mechanism as ost::Server's own
    // _wake_task(), for the same reason (see there): io_uring_enter() can
    // swallow a single interrupting signal.
    rawstd::DetachedTask _wake_task();

public:
    // `listen_fd` must already be bound+listening (see bind_listen()) and
    // `store` must outlive this Server; neither is owned. `wake_fd`, if
    // not -1, is only ever read from -- never closed -- and treated as a
    // stop request the moment it becomes readable; the caller must keep
    // it open for at least as long as this Server runs.
    Server(
        unsigned int queue_size, int listen_fd, ObjectStore& store,
        int wake_fd = -1
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    // Creates, binds and listens a socket on addr:port (SO_REUSEADDR, then
    // listen(SOMAXCONN)), for one or more Servers to share.
    static int bind_listen(const std::string& addr, unsigned int port);

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    ObjectStore& store() noexcept { return _store; }

    rawstd::Task<void> del_client(int fd);
    void loop();
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_SERVER_HPP
