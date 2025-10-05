#ifndef RAWSTORIO_EVENT_HPP
#define RAWSTORIO_EVENT_HPP

#include <rawstorstd/logging.h>

#include <rawstor/io_queue.h>

#include <string>

#include <cstddef>
#include <cstdio>


namespace rawstor {
namespace io {


class Queue;


}} // rawstor::io


struct RawstorIOEvent {
    private:
        rawstor::io::Queue &_q;
        int _fd;
        size_t _size;

        RawstorIOCallback *_cb;
        void *_data;

#ifdef RAWSTOR_TRACE_EVENTS
        void *_trace_id;
#endif

    public:
        RawstorIOEvent(
            rawstor::io::Queue &q,
            int fd, size_t size,
            RawstorIOCallback *cb, void *data);
        RawstorIOEvent(const RawstorIOEvent &) = delete;
        RawstorIOEvent(RawstorIOEvent &&) = delete;
        RawstorIOEvent& operator=(const RawstorIOEvent &) = delete;
        RawstorIOEvent& operator=(RawstorIOEvent &&) = delete;
        virtual ~RawstorIOEvent();

#ifdef RAWSTOR_TRACE_EVENTS
        void trace(const std::string &message) {
            rawstor_trace_event_message(_trace_id, "%s\n", message.c_str());
        }
#endif

        inline rawstor::io::Queue& queue() noexcept {
            return _q;
        }

        inline int fd() const noexcept {
            return _fd;
        }

        inline size_t size() const noexcept {
            return _size;
        }

        virtual size_t result() const noexcept = 0;
        virtual int error() const noexcept = 0;

        void dispatch();
};


#endif // RAWSTORIO_EVENT_HPP
