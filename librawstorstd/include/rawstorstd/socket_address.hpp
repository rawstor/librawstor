#ifndef RAWSTOR_SOCKET_ADDRESS_HPP
#define RAWSTOR_SOCKET_ADDRESS_HPP

#include <rawstor/rawstor.h>

#include <string>

namespace rawstor {


class SocketAddress {
    private:
        std::string _host;
        unsigned int _port;

    public:
        explicit SocketAddress(const RawstorSocketAddress *address):
            _host(address->host != nullptr ? address->host : ""),
            _port(address->port)
        {}

        SocketAddress(const std::string &host, unsigned int port):
            _host(host),
            _port(port)
        {}

        inline const std::string& host() const noexcept {
            return _host;
        }

        inline unsigned int port() const noexcept {
            return _port;
        }
};


} // rawstor

#endif // RAWSTOR_SOCKET_ADDRESS_HPP
