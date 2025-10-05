#include "poll_event.hpp"

#include <rawstorstd/iovec.h>

#include <vector>

#include <sys/types.h>
#include <sys/uio.h>

#include <unistd.h>

namespace rawstor {
namespace io {
namespace poll {


void Event::add_iov(std::vector<iovec> &iov) {
    for (unsigned int i = 0; i < _niov_at; ++i) {
        iov.push_back(_iov_at[i]);
    }
}


size_t Event::shift(size_t shift) {
    size_t ret;
    if (shift >= size()) {
        ret = shift - size();
        _result += size();
        _niov_at = 0;
    } else {
        ret = rawstor_iovec_shift(&_iov_at, &_niov_at, shift);
        _result += shift;
    }
    return ret;
}



size_t EventP::shift(size_t shift) {
    size_t ret = Event::shift(shift);
    _offset += shift - ret;
    return ret;
}


}}} // rawstor::io::poll
