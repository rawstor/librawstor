#ifndef RAWSTOR_VHOST_SERVER_HPP
#define RAWSTOR_VHOST_SERVER_HPP

#include <string>

namespace rawstor {
namespace vhost {

class Server final {
private:
    unsigned int _queue_size;
    std::string _target;
    std::string _socket_path;
    bool _write_cache_enabled;
    bool _readonly;
    /* flock()ed `<socket path>.lock`, held for this Server's whole
     * lifetime: at most one rawstor-vhost serves a given socket path, so
     * whatever socket file it finds there at startup is stale -- see
     * open_unix_socket(). */
    int _lock_fd;
    int _fd;
    int _wake_fd;

public:
    /**
     * `wake_fd`, if not -1, is passed through to the Device built for
     * each accepted connection (see loop()) -- see Device's own
     * constructor doc comment for what it's for. Neither Server nor
     * Device ever closes it; the caller (main.cpp) owns it for as long
     * as this Server runs.
     */
    Server(
        unsigned int queue_size, const std::string& target,
        const std::string& socket_path, bool write_cache_enabled, bool readonly,
        int wake_fd = -1
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    void loop();
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_SERVER_HPP
