#include <rawstorio/event.hpp>

#include <rawstorstd/gpp.hpp>


namespace rawstor {
namespace io {


Event::Event(Queue &q, int fd, size_t size, RawstorIOCallback *cb, void *data):
    _c_ptr(new RawstorIOEvent()),
    _q(q),
    _fd(fd),
    _size(size),
    _cb(cb),
    _data(data)
{
    _c_ptr->impl = this;
}


Event::~Event() {
    delete _c_ptr;
}


void Event::dispatch() {
    int res = _cb(_c_ptr, _data);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


}} // rawstor::io


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->impl->fd();
}

size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->impl->size();
}

size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->impl->result();
}

int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->impl->error();
}


