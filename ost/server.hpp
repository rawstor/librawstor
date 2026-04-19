#ifndef RAWSTOR_OST_SERVER_HPP
#define RAWSTOR_OST_SERVER_HPP

#include <rawstor/rawstor.h>

#include <string>

namespace rawstor {
namespace ost {

class Server final {
private:
    int _fd;
    std::string _uris;
    RawstorIOEvent* _accept_event;

    static int _accept(size_t result, int error, void* data);
    int _accept(size_t result, int error);

public:
    Server(const std::string& addr, unsigned int port, const std::string& uris);
    Server(const Server&) = delete;
    Server(Server&&) = delete;
    ~Server();

    Server& operator=(const Server&) = delete;
    Server& operator=(Server&&) = delete;

    void loop();
};

} // namespace ost
} // namespace rawstor

#endif // RAWSTOR_VHOST_SERVER_HPP
