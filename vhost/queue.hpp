#ifndef RAWSTOR_VHOST_QUEUE_HPP
#define RAWSTOR_VHOST_QUEUE_HPP

#include <deque>
#include <functional>
#include <memory>
#include <thread>

namespace rawstor {
namespace vhost {

class Message;

class Queue final {
private:
    int _size;
    int _pipe_out;
    int _pipe_in;
    std::unique_ptr<std::thread> _thread;
    std::mutex _mutex;
    std::deque<std::unique_ptr<Message>> _messages;

    static void _main(Queue* queue);
    void _loop();
    void _break();

public:
    explicit Queue(unsigned int size);
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;
    ~Queue();

    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;

    void add_watch(int fd, int mask, std::function<void()>&& cb);
    void remove_watch(int fd);
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_QUEUE_HPP
