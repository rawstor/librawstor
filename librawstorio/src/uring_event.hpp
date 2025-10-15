#ifndef RAWSTORIO_URING_EVENT_HPP
#define RAWSTORIO_URING_EVENT_HPP

#include <rawstorio/event.hpp>

#include <rawstor/io_event.h>

#include <liburing.h>

#include <memory>

#include <cstddef>


namespace rawstor {
namespace io {
namespace uring {


class Queue;


class Event: public RawstorIOEvent {
    private:
    protected:
        io_uring_sqe *_sqe;
        io_uring_cqe *_cqe;

    public:
        static std::unique_ptr<Event> read(
            Queue &q, std::unique_ptr<rawstor::io::TaskScalar> t);
        static std::unique_ptr<Event> read(
            Queue &q, std::unique_ptr<rawstor::io::TaskVector> t);
        static std::unique_ptr<Event> read(
            Queue &q, std::unique_ptr<rawstor::io::TaskScalarPositional> t);
        static std::unique_ptr<Event> read(
            Queue &q, std::unique_ptr<rawstor::io::TaskVectorPositional> t);
        static std::unique_ptr<Event> write(
            Queue &q, std::unique_ptr<rawstor::io::TaskScalar> t);
        static std::unique_ptr<Event> write(
            Queue &q, std::unique_ptr<rawstor::io::TaskVector> t);
        static std::unique_ptr<Event> write(
            Queue &q, std::unique_ptr<rawstor::io::TaskScalarPositional> t);
        static std::unique_ptr<Event> write(
            Queue &q, std::unique_ptr<rawstor::io::TaskVectorPositional> t);

        Event(
            Queue &q,
            std::unique_ptr<rawstor::io::Task> t);
        ~Event();

        inline void set_cqe(io_uring_cqe *cqe) noexcept {
            _cqe = cqe;
        }

        size_t result() const noexcept;
        int error() const noexcept;
};


}}} // rawstor::io::uring

#endif // RAWSTORIO_URING_EVENT_HPP

