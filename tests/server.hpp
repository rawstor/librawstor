#ifndef RAWSTOR_TESTS_SERVER_HPP
#define RAWSTOR_TESTS_SERVER_HPP

#include <condition_variable>
#include <deque>
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

    static void _main(Server* server);
    void _loop();

    void _do_accept(Command& command);
    void _do_close(Command& command);
    void _do_read(Command& command);
    void _do_write(Command& command);

    void _stop();

public:
    explicit Server(int port);
    ~Server();

    void accept();

    void close();
    void read(void* buf, size_t size);
    void write(const void* buf, size_t size);

    void wait();
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_SERVER_HPP
