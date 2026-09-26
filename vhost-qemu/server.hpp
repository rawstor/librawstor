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
    int _fd;

public:
    Server(
        unsigned int queue_size, const std::string& target,
        const std::string& socket_path, bool write_cache_enabled, bool readonly
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
