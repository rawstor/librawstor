#ifndef RAWSTORIO_POLL_SESSION_HPP
#define RAWSTORIO_POLL_SESSION_HPP

#include "poll_event.hpp"
#include "poll_queue.hpp"

#include <rawstorstd/ringbuf.hpp>

#include <list>
#include <memory>

#include <poll.h>

namespace rawstor {
namespace io {
namespace poll {

class Session final {
private:
    Queue& _q;
    int _fd;
    std::list<std::unique_ptr<EventSimplexPoll>> _poll_sqes;
    rawstor::RingBuf<Event> _read_sqes;
    rawstor::RingBuf<Event> _write_sqes;

    void _process_poll(rawstor::RingBuf<Event>& cqes, short revents);

    void _process_simplex(
        std::unique_ptr<EventSimplex> event, rawstor::RingBuf<Event>& cqes
    );

    void _process_multiplex(
        std::vector<std::unique_ptr<EventMultiplex>>& events, unsigned int niov,
        rawstor::RingBuf<Event>& sqes, rawstor::RingBuf<Event>& cqes, bool write
    );

    void _process(
        rawstor::RingBuf<Event>& sqes, rawstor::RingBuf<Event>& cqes, bool write
    );

public:
    Session(Queue& q, int fd);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    inline int fd() const noexcept { return _fd; }

    short events() const noexcept;

    inline bool empty() const noexcept {
        return _poll_sqes.empty() && _read_sqes.empty() && _write_sqes.empty();
    }

    rawstor::io::Event* poll(std::unique_ptr<rawstor::io::TaskPoll> t);

    rawstor::io::Event* read(std::unique_ptr<rawstor::io::TaskScalar> t);

    rawstor::io::Event* read(std::unique_ptr<rawstor::io::TaskVector> t);

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskScalarPositional> t);

    rawstor::io::Event*
    read(std::unique_ptr<rawstor::io::TaskVectorPositional> t);

    rawstor::io::Event* read(std::unique_ptr<rawstor::io::TaskMessage> t);

    rawstor::io::Event* write(std::unique_ptr<rawstor::io::TaskScalar> t);

    rawstor::io::Event* write(std::unique_ptr<rawstor::io::TaskVector> t);

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskScalarPositional> t);

    rawstor::io::Event*
    write(std::unique_ptr<rawstor::io::TaskVectorPositional> t);

    rawstor::io::Event* write(std::unique_ptr<rawstor::io::TaskMessage> t);

    void process(RingBuf<Event>& cqes, short revents);
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_SESSION_POLL_HPP
