#ifndef RAWSTORIO_BASE_EVENT_HPP
#define RAWSTORIO_BASE_EVENT_HPP

#include <rawstorstd/gpp.hpp>

#include <rawstor/io_queue.h>

#include <cstddef>
#include <cstdio>


namespace rawstor {
namespace io {
namespace base {


class Event {
    private:
        RawstorIOEvent *_c_ptr;
        RawstorIOCallback *_cb;
        void *_data;

    protected:
        int _fd;
        size_t _size;

    public:
        Event(int fd, size_t size, RawstorIOCallback *cb, void *data);
        Event(const Event &) = delete;
        Event(Event &&) = delete;
        Event& operator=(const Event &) = delete;
        Event& operator=(Event &&) = delete;
        virtual ~Event();

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

        inline void dispatch() {
            int res = _cb(_c_ptr, _data);
            if (res) {
                RAWSTOR_THROW_SYSTEM_ERROR(-res);
            }
        }
};


}}} // rawstor::io::base


struct RawstorIOEvent {
    rawstor::io::base::Event *impl;
};


#endif // RAWSTORIO_BASE_EVENT_HPP
