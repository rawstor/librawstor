#ifndef RAWSTORIO_TESTS_SOCKET_HPP
#define RAWSTORIO_TESTS_SOCKET_HPP

#include <string>
#include <utility>

namespace rawstor {
namespace io {
namespace tests {

class Socket final {
private:
    int _fd;
    std::string _name;

public:
    Socket();
    Socket(const Socket&) = delete;
    Socket(Socket&& other) noexcept :
        _fd(std::exchange(other._fd, -1)),
        _name(std::exchange(other._name, std::string())) {}
    ~Socket();

    Socket& operator=(const Socket&) = delete;
    Socket& operator=(Socket&& other) noexcept {
        Socket temp(std::move(other));
        swap(temp);
        return *this;
    }

    void swap(Socket& other) noexcept {
        std::swap(_fd, other._fd);
        std::swap(_name, other._name);
    }

    int fd() const noexcept { return _fd; }

    void listen();
    void connect(const Socket& other);
    const std::string& name() const noexcept { return _name; }
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_SOCKET_HPP
