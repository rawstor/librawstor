#include <rawstorio/base_event.hpp>


namespace rawstor {
namespace io {
namespace base {


Event::Event(int fd, size_t size, RawstorIOCallback *cb, void *data):
    _c_ptr(new RawstorIOEvent()),
    _cb(cb),
    _data(data),
    _fd(fd),
    _size(size)
{
    _c_ptr->impl = this;
}


Event::~Event() {
    delete _c_ptr;
}


}}} // rawstor::io::base


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


