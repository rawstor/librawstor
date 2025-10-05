#include <rawstorio/event.hpp>

#include <rawstorstd/gpp.hpp>


RawstorIOEvent::RawstorIOEvent(
    rawstor::io::Queue &q,
    int fd, size_t size,
    RawstorIOCallback *cb, void *data):
    _q(q),
    _fd(fd),
    _size(size),
    _cb(cb),
    _data(data)
{}


void RawstorIOEvent::dispatch() {
    int res = _cb(this, _data);
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
}


int rawstor_io_event_fd(RawstorIOEvent *event) {
    return event->fd();
}

size_t rawstor_io_event_size(RawstorIOEvent *event) {
    return event->size();
}

size_t rawstor_io_event_result(RawstorIOEvent *event) {
    return event->result();
}

int rawstor_io_event_error(RawstorIOEvent *event) {
    return event->error();
}
