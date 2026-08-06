#ifndef RAWSTOR_VDUSE_SERVER_HPP
#define RAWSTOR_VDUSE_SERVER_HPP

#include <string>

namespace rawstor {
namespace vduse {

class Server final {
private:
    unsigned int _queue_size;
    std::string _target;
    std::string _name;
    std::string _reconnect_file;
    bool _write_cache_enabled;

public:
    Server(
        unsigned int queue_size, const std::string& target,
        const std::string& name, const std::string& reconnect_file,
        bool write_cache_enabled
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    void loop();
};

} // namespace vduse
} // namespace rawstor

#endif // RAWSTOR_VDUSE_SERVER_HPP
