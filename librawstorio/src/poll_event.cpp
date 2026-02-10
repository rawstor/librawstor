#include "poll_event.hpp"

#include <rawstorstd/iovec.h>

#include <sstream>
#include <vector>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {
namespace poll {

void Event::dispatch() {
    RAWSTOR_TRACE_EVENT_MESSAGE(_t->trace_event, "callback");
    try {
        (*_t)(_result, _error);
    } catch (const std::exception& e) {
        RAWSTOR_TRACE_EVENT_MESSAGE(
            _t->trace_event, "callback error: " << e.what()
        );
        throw;
    }
    RAWSTOR_TRACE_EVENT_MESSAGE(_t->trace_event, "callback success");
}

void Event::add_iov(std::vector<iovec>& iov) {
    for (unsigned int i = 0; i < _niov_at; ++i) {
        iov.push_back(_iov_at[i]);
    }
}

size_t Event::shift(size_t shift) {
    size_t ret;
    if (shift >= _size) {
        ret = shift - _size;
        _result += _size;
        _niov_at = 0;
    } else {
        ret = shift - rawstor_iovec_discard_front(&_iov_at, &_niov_at, shift);
        _result += shift;
    }
    return ret;
}

size_t EventP::shift(size_t shift) {
    size_t ret = Event::shift(shift);
    _offset_at += shift - ret;
    return ret;
}

} // namespace poll
} // namespace io
} // namespace rawstor
