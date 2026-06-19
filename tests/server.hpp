#ifndef RAWSTOR_TESTS_SERVER_HPP
#define RAWSTOR_TESTS_SERVER_HPP

#include <sys/uio.h>

#include <condition_variable>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include <cstddef>

namespace rawstor {
namespace tests {

class Command;

class Server {
private:
    int _fd;
    int _client_fd;

    std::unique_ptr<std::thread> _thread;

    std::deque<std::shared_ptr<Command>> _commands;

    std::condition_variable _push_condition;
    std::condition_variable _pop_condition;
    std::mutex _mutex;

    std::shared_ptr<Command> _pop_command();
    static void _main(Server* server) noexcept;
    void _loop();

    void _do_accept(Command& command);
    void _do_close(Command& command);
    void _do_read(Command& command);
    void _do_write(Command& command);
    void _do_writev(Command& command);

    void _stop();

public:
    explicit Server(int port);
    ~Server();

    void accept(const char* name);

    void close(const char* name);
    void read(
        const char* name, size_t size,
        std::function<void(const void* buf, size_t result)>&& cb
    );
    void write(const char* name, const void* buf, size_t size);
    void writev(const char* name, const iovec* iov, unsigned int niov);

    void wait();
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_SERVER_HPP
