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

class Session;

// Single-instance MDS server (rawstor_docs/Mds.md, "MDS server, v1"):
// owns its own listening socket and VolumeStore, one worker (VolumeStore's
// calls are synchronous and rare -- a briefly blocked event loop is
// accepted, see VolumeStore's own doc comment), no accept_multishot
// sharing across threads unlike ost::Server.
class Server final {
private:
    RawIOQueue* _queue;
    int _fd;
    int _wake_fd;
    bool _stop;
    VolumeStore _store;
    RawIOEvent* _accept_event;
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;

    rawstd::DetachedTask _accept_task();
    rawstd::Task<void> _add_session(int fd);

    // Only launched when `wake_fd` (the constructor's last argument) holds
    // a real fd -- same self-pipe shutdown mechanism as ost::Server's own
    // _wake_task(), for the same reason (see there): io_uring_enter() can
    // swallow a single interrupting signal.
    rawstd::DetachedTask _wake_task();

public:
    // `wake_fd`, if not -1, is only ever read from -- never closed --
    // and treated as a stop request the moment it becomes readable; the
    // caller must keep it open for at least as long as this Server runs.
    Server(
        unsigned int queue_size, const std::string& addr, unsigned int port,
        const std::string& db_path, Topology topology, int wake_fd = -1
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    VolumeStore& store() noexcept { return _store; }

    rawstd::Task<void> del_session(int fd);
    void loop();
};

} // namespace mds
} // namespace rawstor

#endif // RAWSTOR_MDS_SERVER_HPP
