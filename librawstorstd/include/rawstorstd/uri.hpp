#ifndef RAWSTORSTD_URI_HPP
#define RAWSTORSTD_URI_HPP

#include <string>


namespace rawstor {


class URIPath {
    private:
        std::string _path;
        std::string _dirname;
        std::string _filename;

    public:
        URIPath() {}
        explicit URIPath(const std::string &path);
        URIPath(const URIPath &other);
        URIPath(URIPath &&other) noexcept;
        URIPath& operator=(const URIPath &other);
        URIPath& operator=(URIPath &&other) noexcept;

        inline const std::string& str() const noexcept {
            return _path;
        }

        inline const std::string& dirname() const noexcept {
            return _dirname;
        }

        inline const std::string& filename() const noexcept {
            return _filename;
        }
};


class URI {
    private:
        std::string _uri;
        std::string _scheme;
        std::string _userinfo;
        std::string _username;
        std::string _password;
        std::string _authority;
        std::string _host;
        std::string _hostname;
        unsigned int _port;
        URIPath _path;

    public:
        explicit URI(const std::string &uri);
        URI(const URI &other);
        URI(URI &&other) noexcept;
        URI& operator=(const URI &other);
        URI& operator=(URI &&other) noexcept;

        URI up() const;

        inline const std::string& str() const noexcept {
            return _uri;
        }

        inline const std::string& scheme() const noexcept {
            return _scheme;
        }

        inline const std::string& userinfo() const noexcept {
            return _userinfo;
        }

        inline const std::string& username() const noexcept {
            return _username;
        }

        inline const std::string& password() const noexcept {
            return _password;
        }

        inline const std::string& authority() const noexcept {
            return _authority;
        }

        inline const std::string& host() const noexcept {
            return _host;
        }

        inline const std::string& hostname() const noexcept {
            return _hostname;
        }

        inline unsigned int port() const noexcept {
            return _port;
        }

        inline const URIPath& path() const noexcept {
            return _path;
        }
};


} // rawstor

#endif // RAWSTORSTD_URI_HPP
