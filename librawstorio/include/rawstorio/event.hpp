#ifndef RAWSTORIO_EVENT_HPP
#define RAWSTORIO_EVENT_HPP

#include <rawstor/io_queue.h>

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

    public:
        RawstorIOEvent(
            rawstor::io::Queue &q,
            int fd, size_t size,
            RawstorIOCallback *cb, void *data);
        RawstorIOEvent(const RawstorIOEvent &) = delete;
        RawstorIOEvent(RawstorIOEvent &&) = delete;
        RawstorIOEvent& operator=(const RawstorIOEvent &) = delete;
        RawstorIOEvent& operator=(RawstorIOEvent &&) = delete;
        virtual ~RawstorIOEvent() {}

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
