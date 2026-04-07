#ifndef RAWSTOR_OSTBACKEND_SERVER_HPP
#define RAWSTOR_OSTBACKEND_SERVER_HPP

#include <rawstorstd/uri.hpp>

#include <rawstor/rawstor.h>

#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace rawstor {
namespace ostbackend {

class Session;

class Server final {
private:
    int _fd;
    std::vector<rawstor::URI> _uris;
    RawstorIOEvent* _accept_event;
    std::unordered_map<int, std::unique_ptr<Session>> _sessions;

    static int _accept(size_t result, int error, void* data);
    int _accept(size_t result, int error);
    void _add_session(int fd);

public:
    Server(const std::string& addr, unsigned int port, const char* uris);
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    inline const std::vector<rawstor::URI>& uris() const noexcept {
        return _uris;
    }

    void del_session(int fd);
    void loop();
};

} // namespace ostbackend
} // namespace rawstor

#endif // RAWSTOR_OSTBACKEND_SERVER_HPP
