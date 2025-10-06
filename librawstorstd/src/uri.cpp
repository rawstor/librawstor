#include "rawstorstd/uri.hpp"

#include <string>
#include <sstream>
#include <utility>

namespace {


void parse(
    const std::string &uri,
    std::string *scheme,
    std::string *username, std::string *password,
    std::string *hostname, unsigned int *port,
    std::string *path)
{
    size_t scheme_delim = uri.find("://");
    if (scheme_delim != uri.npos) {
        *scheme = uri.substr(0, scheme_delim);
        scheme_delim += 3;
    } else {
        *scheme = "";
        scheme_delim = 0;
    }

    size_t at_delim = uri.find('@', scheme_delim);
    if (at_delim != uri.npos) {
        at_delim += 1;
        size_t colon_delim = uri.find(":", scheme_delim);
        if (colon_delim != uri.npos && colon_delim < at_delim) {
            colon_delim += 1;
            *username = uri.substr(
                scheme_delim, colon_delim - scheme_delim - 1);
            *password = uri.substr(colon_delim, at_delim - colon_delim - 1);
        } else {
            *username = uri.substr(scheme_delim, at_delim - scheme_delim);
            *password = "";
        }
    } else {
        *username = "";
        *password = "";
        at_delim = scheme_delim;
    }

    size_t path_delim = uri.find('/', at_delim);
    if (path_delim == uri.npos) {
        path_delim = uri.length();
    }

    size_t colon_delim = uri.find(":", at_delim);
    if (colon_delim != uri.npos && colon_delim < path_delim) {
        *hostname = uri.substr(at_delim, colon_delim - at_delim);
        colon_delim += 1;
        std::istringstream iss(
            uri.substr(colon_delim, path_delim - colon_delim));
        iss >> *port;
    } else {
        *hostname = uri.substr(at_delim, path_delim - at_delim);
        *port = 0;
    }

    *path = uri.substr(path_delim);
}


std::string get_userinfo(
    const std::string &username, const std::string &password)
{
    std::ostringstream oss;

    oss << username;
    if (!password.empty()) {
        oss << ":" << password;
    }

    return oss.str();
}


std::string get_host(
    const std::string &hostname, unsigned int port)
{
    std::ostringstream oss;

    oss << hostname;
    if (port != 0) {
        oss << ":" << port;
    }

    return oss.str();
}


std::string get_authority(
    const std::string &userinfo, const std::string &host)
{
    std::ostringstream oss;

    if (!userinfo.empty()) {
        oss << userinfo << "@";
    }
    oss << host;

    return oss.str();
}


} // unnamed

namespace rawstor {


URI::URI(const std::string &uri):
    _uri(uri)
{
    parse(_uri, &_scheme, &_username, &_password, &_hostname, &_port, &_path);

    _userinfo = get_userinfo(_username, _password);
    _host = get_host(_hostname, _port);
    _authority = get_authority(_userinfo, _host);
}


URI::URI(const URI &other):
    _uri(other._uri),
    _scheme(other._scheme),
    _userinfo(other._userinfo),
    _username(other._username),
    _password(other._password),
    _authority(other._authority),
    _host(other._host),
    _hostname(other._hostname),
    _port(other._port),
    _path(other._path)
{}


URI::URI(URI &&other) noexcept:
    _uri(std::move(other._uri)),
    _scheme(std::move(other._scheme)),
    _userinfo(std::move(other._userinfo)),
    _username(std::move(other._username)),
    _password(std::move(other._password)),
    _authority(std::move(other._authority)),
    _host(std::move(other._host)),
    _hostname(std::move(other._hostname)),
    _port(std::exchange(other._port, 0)),
    _path(std::move(other._path))
{}


URI& URI::operator=(const URI &other) {
    if (this != &other) {
        URI copy(other);

        _uri = std::move(copy._uri);
        _scheme = std::move(copy._scheme);
        _userinfo = std::move(copy._userinfo);
        _username = std::move(copy._username);
        _password = std::move(copy._password);
        _authority = std::move(copy._authority);
        _host = std::move(copy._host);
        _hostname = std::move(copy._hostname);
        _port = std::exchange(copy._port, 0);
        _path = std::move(copy._path);
    }
    return *this;
}


URI& URI::operator=(URI &&other) noexcept {
    if (this != &other) {
        _uri = std::move(other._uri);
        _scheme = std::move(other._scheme);
        _userinfo = std::move(other._userinfo);
        _username = std::move(other._username);
        _password = std::move(other._password);
        _authority = std::move(other._authority);
        _host = std::move(other._host);
        _hostname = std::move(other._hostname);
        _port = std::exchange(other._port, 0);
        _path = std::move(other._path);
    }
    return *this;
}


} // rawstor
