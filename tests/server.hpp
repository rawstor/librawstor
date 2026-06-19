#ifndef RAWSTOR_TESTS_SERVER_HPP
#define RAWSTOR_TESTS_SERVER_HPP

#include <rawio/queue.hpp>

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
    int _in;
    int _out;
    bool _exit;
    int _client_fd;
    unsigned int _depth;

    std::unique_ptr<std::thread> _thread;

    std::mutex _mutex;
    std::deque<std::shared_ptr<Command>> _commands;

    static void _main(Server* server) noexcept;
    void _notify();
    void _loop();

    void _do_accept(rawio::Queue& queue, std::shared_ptr<Command> command);
    void _do_close(rawio::Queue& queue, std::shared_ptr<Command> command);
    void _do_read(rawio::Queue& queue, std::shared_ptr<Command> command);
    void _do_write(rawio::Queue& queue, std::shared_ptr<Command> command);
    void _do_writev(rawio::Queue& queue, std::shared_ptr<Command> command);

    void _stop();

public:
    Server(int port, unsigned int depth);
    ~Server();

    void accept(const char* name);

    void close(const char* name);
    void read(
        const char* name, size_t size, std::function<void(const void* buf)>&& cb
    );
    void write(const char* name, const void* buf, size_t size);
    void writev(const char* name, const iovec* iov, unsigned int niov);
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_SERVER_HPP
