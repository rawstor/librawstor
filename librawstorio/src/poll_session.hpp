#ifndef RAWSTORIO_POLL_SESSION_HPP
#define RAWSTORIO_POLL_SESSION_HPP

#include "poll_event.hpp"
#include "poll_queue.hpp"

#include <rawstorstd/ringbuf.hpp>

#include <memory>
#include <poll.h>

namespace rawstor {
namespace io {
namespace poll {


class Session final {
    private:
        Queue &_q;
        int _fd;
        rawstor::RingBuf<Event> _read_sqes;
        rawstor::RingBuf<Event> _write_sqes;

        void _process_simplex(
            std::unique_ptr<EventSimplex> event,
            rawstor::RingBuf<Event> &cqes,
            bool write, bool pollhup);

        void _process_multiplex(
            std::vector<std::unique_ptr<EventMultiplex>> &events,
            unsigned int niov,
            rawstor::RingBuf<Event> &sqes,
            rawstor::RingBuf<Event> &cqes,
            bool write, bool pollhup);

        void _process(
            rawstor::RingBuf<Event> &sqes,
            rawstor::RingBuf<Event> &cqes,
            bool write, bool pollhup);

    public:
        Session(Queue &q, int fd);
        Session(const Session &) = delete;
        Session(Session &&) = delete;
        Session& operator=(const Session &) = delete;
        Session& operator=(Session &&) = delete;

        inline int fd() const noexcept {
            return _fd;
        }

        inline short events() const noexcept {
            return
                (_read_sqes.empty() ? 0 : POLLIN) |
                (_write_sqes.empty() ? 0 : POLLOUT);
        }

        inline bool empty() const noexcept {
            return _read_sqes.empty() && _write_sqes.empty();
        }

        void read(std::unique_ptr<rawstor::io::TaskScalar> t);

        void read(std::unique_ptr<rawstor::io::TaskVector> t);

        void read(std::unique_ptr<rawstor::io::TaskScalarPositional> t);

        void read(std::unique_ptr<rawstor::io::TaskVectorPositional> t);

        void read(std::unique_ptr<rawstor::io::TaskMessage> t);

        void write(std::unique_ptr<rawstor::io::TaskScalar> t);

        void write(std::unique_ptr<rawstor::io::TaskVector> t);

        void write(std::unique_ptr<rawstor::io::TaskScalarPositional> t);

        void write(std::unique_ptr<rawstor::io::TaskVectorPositional> t);

        void write(std::unique_ptr<rawstor::io::TaskMessage> t);

        void process_read(RingBuf<Event> &cqes, bool pollhup);

        void process_write(RingBuf<Event> &cqes, bool pollhup);
};


}}} // rawstor::io

#endif // RAWSTORIO_SESSION_POLL_HPP
