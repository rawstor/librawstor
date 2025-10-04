#ifndef RAWSTORIO_EVENT_HPP
#define RAWSTORIO_EVENT_HPP

#include <rawstor/io_queue.h>

#include <cstddef>
#include <cstdio>


namespace rawstor {
namespace io {


class Queue;


class Event {
    private:
        RawstorIOEvent *_c_ptr;

        Queue &_q;
        int _fd;
        size_t _size;

        RawstorIOCallback *_cb;
        void *_data;

    public:
        Event(
            Queue &q, int fd, size_t size, RawstorIOCallback *cb, void *data);
        Event(const Event &) = delete;
        Event(Event &&) = delete;
        Event& operator=(const Event &) = delete;
        Event& operator=(Event &&) = delete;
        virtual ~Event();

        inline Queue& queue() noexcept {
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

        inline RawstorIOEvent* c_ptr() const noexcept {
            return _c_ptr;
        }

        void dispatch();
};


}} // rawstor::io


struct RawstorIOEvent {
    rawstor::io::Event *impl;
};


#endif // RAWSTORIO_BASE_EVENT_HPP
