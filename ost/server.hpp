#ifndef RAWSTOR_OSTBACKEND_SERVER_HPP
#define RAWSTOR_OSTBACKEND_SERVER_HPP

#include <rawstd/uri.hpp>

#include <rawstor/rawio.h>

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
    std::unordered_map<int, std::unique_ptr<Session>> _sessions;

    static int _accept(size_t result, int error, void* data) noexcept;
    int _accept(size_t result, int error);
    void _add_session(int fd);

public:
    Server(const std::string& addr, unsigned int port, const char* location);
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    inline const std::vector<rawstd::URI>& locations() const noexcept {
        return _locations;
    }

    void del_session(int fd) noexcept;
    void loop();
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SERVER_HPP
