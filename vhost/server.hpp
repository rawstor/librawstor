#ifndef RAWSTOR_VHOST_SERVER_HPP
#define RAWSTOR_VHOST_SERVER_HPP

#include <string>

namespace rawstor {
namespace vhost {

class Server final {
private:
    unsigned int _num_queues;
    unsigned int _queue_size;
    std::string _target;
    std::string _socket_path;
    int _fd;

public:
    Server(
        unsigned int num_queues, unsigned int queue_size,
        const std::string& target, const std::string& socket_path
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
