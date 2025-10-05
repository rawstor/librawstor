#include <rawstorstd/socket_address.hpp>

#include <sstream>
#include <string>

namespace rawstor {


std::string SocketAddress::str() const {
    std::ostringstream oss;
    oss << host() << ":" << port();
    return oss.str();
}


} // rawstor
