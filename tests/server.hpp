#ifndef RAWSTOR_TESTS_SERVER_HPP
#define RAWSTOR_TESTS_SERVER_HPP

#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

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
    int _client_fd;
    unsigned int _depth;

    std::unique_ptr<std::thread> _thread;

    std::mutex _mutex;
    std::deque<std::shared_ptr<Command>> _commands;

    static void _main(Server* server) noexcept;
    void _notify();
    void _loop();
    // Pops and dispatches one command per iteration, blocking on the
    // self-pipe (_out) only when the queue is empty -- a caller only
    // _notify()'s on the empty-to-non-empty transition, so draining a
    // burst of several commands pushed under one notification relies on
    // this loop re-checking _commands directly rather than waiting for a
    // matching pipe byte per command.
    rawstd::Task<void> _run(rawio::Queue& queue);

    rawstd::Task<void>
    _do_accept(rawio::Queue& queue, std::shared_ptr<Command> command);
    void _do_close(rawio::Queue& queue, std::shared_ptr<Command> command);
    void _do_forget(rawio::Queue& queue, std::shared_ptr<Command> command);
    rawstd::Task<void>
    _do_read(rawio::Queue& queue, std::shared_ptr<Command> command);
    rawstd::Task<void>
    _do_write(rawio::Queue& queue, std::shared_ptr<Command> command);
    rawstd::Task<void>
    _do_writev(rawio::Queue& queue, std::shared_ptr<Command> command);

    void _stop();

public:
    Server(int port, unsigned int depth);
    ~Server();

    void accept(const char* name);

    void close(const char* name);
    // Like close(), but drops this end's own bookkeeping of the
    // connection (so a later accept() is free to track a new one)
    // without actually closing the fd or sending anything on the wire --
    // for a test that needs the client to be the *only* side that ever
    // notices this connection going away (a server-initiated close would
    // send a FIN the client's own recv side could race to notice first).
    // The fd itself is left for the OS to reclaim at process exit.
    void forget(const char* name);
    void read(
        const char* name, size_t size, std::function<void(const void* buf)>&& cb
    );
    void write(const char* name, const void* buf, size_t size);
    void writev(const char* name, const iovec* iov, unsigned int niov);
};

} // namespace tests
} // namespace rawstor

#endif // RAWSTOR_TESTS_SERVER_HPP
