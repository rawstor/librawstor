#ifndef RAWSTOR_VHOST_SERVER_HPP
#define RAWSTOR_VHOST_SERVER_HPP

#include <string>


namespace rawstor {
namespace vhost {


class Server final {
    private:
        std::string _socket_path;
        int _fd;

    public:
        Server(const std::string &object_uri, const std::string &socket_path);
        Server(const Server &) = delete;
        Server(Server &&) = delete;
        ~Server();

        Server& operator=(const Server &) = delete;
        Server& operator=(Server &&) = delete;

        void loop();
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_SERVER_HPP
