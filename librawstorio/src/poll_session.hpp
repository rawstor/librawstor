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
    int _fd;
    std::list<std::unique_ptr<EventSimplexPoll>> _poll_sqes;
    rawstor::RingBuf<EventSimplex> _read_sqes;
    rawstor::RingBuf<Event> _write_sqes;

    void _process_poll(rawstor::RingBuf<Event>& cqes, short revents);

    void _process_simplex_read(
        std::unique_ptr<EventSimplex> event, rawstor::RingBuf<Event>& cqes
    );

    void _process_simplex_write(
        std::unique_ptr<EventSimplex> event, rawstor::RingBuf<Event>& cqes
    );

    void _process_multiplex_write(
        std::vector<std::unique_ptr<EventMultiplex>>& events, unsigned int niov,
        rawstor::RingBuf<Event>& cqes
    );

    void _process_read(rawstor::RingBuf<Event>& cqes);

    void _process_write(rawstor::RingBuf<Event>& cqes);

public:
    Session(int fd, unsigned int depth);
    Session(const Session&) = delete;
    Session(Session&&) = delete;
    Session& operator=(const Session&) = delete;
    Session& operator=(Session&&) = delete;

    inline int fd() const noexcept { return _fd; }

    short events() const noexcept;

    inline bool empty() const noexcept {
        return _poll_sqes.empty() && _read_sqes.empty() && _write_sqes.empty();
    }

    void poll(std::unique_ptr<EventSimplexPoll> event);

    void read(std::unique_ptr<EventSimplex> event);

    void write(std::unique_ptr<Event> event);

    bool cancel(rawstor::io::Event* event, rawstor::RingBuf<Event>& cqes);

    void process(RingBuf<Event>& cqes, short revents);
};

} // namespace poll
} // namespace io
} // namespace rawstor

#endif // RAWSTORIO_SESSION_POLL_HPP
