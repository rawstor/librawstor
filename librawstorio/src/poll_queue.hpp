#ifndef RAWSTORIO_POLL_QUEUE_HPP
#define RAWSTORIO_POLL_QUEUE_HPP

#include <rawstorio/queue.hpp>

#include <rawstorstd/ringbuf.hpp>

#include <unordered_map>
#include <memory>
#include <string>


namespace rawstor {
namespace io {
namespace poll {


class Event;

class Session;


class Queue: public rawstor::io::Queue {
    private:
        std::unordered_map<int, std::shared_ptr<Session>> _sessions;
        rawstor::RingBuf<Event*> _cqes;

        Session& _get_session(int fd);

    public:
        static const std::string& engine_name();
        static void setup_fd(int fd);

        Queue(unsigned int depth):
            rawstor::io::Queue(depth),
            _cqes(depth)
        {}

        void read(
            std::unique_ptr<rawstor::io::TaskScalar> t) override;

        void read(
            std::unique_ptr<rawstor::io::TaskVector> t) override;

        void read(
            std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

        void read(
            std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

        void write(
            std::unique_ptr<rawstor::io::TaskScalar> t) override;

        void write(
            std::unique_ptr<rawstor::io::TaskVector> t) override;

        void write(
            std::unique_ptr<rawstor::io::TaskScalarPositional> t) override;

        void write(
            std::unique_ptr<rawstor::io::TaskVectorPositional> t) override;

        bool empty() const noexcept override;

        void wait(unsigned int timeout) override;
};


}}} // rawstor::io::poll


#endif // RAWSTORIO_POLL_QUEUE_HPP
