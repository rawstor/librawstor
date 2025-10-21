#ifndef RAWSTOR_VHOST_SERVER_HPP
#define RAWSTOR_VHOST_SERVER_HPP

#include <string>


namespace rawstor {
namespace vhost {


void server(const std::string &object_uri, const std::string &socket_path);


}}


#endif // RAWSTOR_VHOST_SERVER_HPP
