#ifndef RAWSTORIO_TESTS_SERVER_HPP
#define RAWSTORIO_TESTS_SERVER_HPP

#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

#include <cstddef>

namespace rawstor {
namespace io {
namespace tests {

class Command;

class Server {
private:
    char* _name;
    int _fd;
    int _client_fd;
    std::vector<char> _buf;

    std::unique_ptr<std::thread> _thread;

    std::unique_ptr<Command> _command;

    std::condition_variable _condition;
    std::mutex _mutex;

    static void _main(Server* server);
    void _loop();

    void _do_accept(Command& command);
    void _do_close(Command& command);
    void _do_read(Command& command);
    void _do_write(Command& command);

    void _accept();
    void _stop();

public:
    Server();
    ~Server();

    inline const char* name() const noexcept { return _name; }

    void close();
    void read(size_t size);
    void write(const void* data, size_t size);

    void wait();

    const char* buf() const noexcept;
    size_t buf_size() const noexcept;
};

} // namespace tests
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_TESTS_SERVER_HPP
