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
#ifdef RAWSTOR_TRACE_EVENTS
    trace("callback");
    try {
#endif
        (*_t)(_result, _error);
#ifdef RAWSTOR_TRACE_EVENTS
    } catch (std::exception &e) {
        std::ostringstream oss;
        oss << "callback error: " << e.what();
        trace(oss.str());
        throw;
    }
    trace("callback success");
#endif
}


void Event::add_iov(std::vector<iovec> &iov) {
    for (unsigned int i = 0; i < _niov_at; ++i) {
        iov.push_back(_iov_at[i]);
    }
}


size_t Event::shift(size_t shift) {
    size_t ret;
    if (shift >= _t->size()) {
        ret = shift - _t->size();
        _result += _t->size();
        _niov_at = 0;
    } else {
        ret = rawstor_iovec_shift(&_iov_at, &_niov_at, shift);
        _result += shift;
    }
    return ret;
}


size_t EventP::shift(size_t shift) {
    size_t ret = Event::shift(shift);
    _offset_at += shift - ret;
    return ret;
}


}}} // rawstor::io::poll
