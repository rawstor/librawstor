#ifndef RAWSTOR_MDSBACKEND_SERVER_HPP
#define RAWSTOR_MDSBACKEND_SERVER_HPP

#include "store.hpp"

#include <rawstor/rawio.h>

#include <memory>
#include <string>
#include <unordered_map>

namespace rawstor {
namespace mdsbackend {

class Session;

class Server final {
private:
    RawIOQueue* _queue;
    int _fd;
    mds::VolumeStore _store;
    RawIOEvent* _accept_event;
    std::unordered_map<int, std::unique_ptr<Session>> _sessions;

    static int _accept(int result, void* data) noexcept;
    int _accept(int result);
    void _add_session(int fd);

public:
    Server(
        unsigned int queue_size, const std::string& addr, unsigned int port,
        const std::string& db_path, const std::string& topology_path
    );
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    mds::VolumeStore& store() noexcept { return _store; }

    void del_session(int fd) noexcept;
    void loop();
};

} // namespace mdsbackend
} // namespace rawstor

#endif // RAWSTOR_MDSBACKEND_SERVER_HPP
