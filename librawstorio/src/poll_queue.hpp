#ifndef RAWSTORIO_POLL_QUEUE_HPP
#define RAWSTORIO_POLL_QUEUE_HPP

#include "poll_event.hpp"

#include <rawstorio/queue.hpp>

#include <rawstorstd/ringbuf.hpp>

#include <memory>
#include <string>
#include <unordered_map>

namespace rawstor {
namespace io {
namespace poll {

class Event;

class Session;

class Queue final : public rawstor::io::Queue {
private:
    std::unordered_map<int, std::shared_ptr<Session>> _sessions;
    rawstor::RingBuf<Event> _cqes;

    Session& _get_session(int fd);

public:
    static const std::string& engine_name();
    static void setup_fd(int fd);

    explicit Queue(unsigned int depth) :
        rawstor::io::Queue(depth),
        _cqes(depth) {}

    rawstor::io::Event* poll(std::unique_ptr<rawstor::io::TaskPoll> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskScalar> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskVector> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskMessage> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskScalar> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskVector> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskMessage> t) override;

    void cancel(rawstor::io::Event* e) override;

    bool empty() const noexcept override;

    void wait(unsigned int timeout) override;
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_POLL_QUEUE_HPP
