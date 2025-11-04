#include "virtq.hpp"

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <unistd.h>

#include <cerrno>
#include <cstring>


namespace rawstor {
namespace vhost {


Virtq::~Virtq() {
    if (_call_fd != -1) {
        rawstor_info("fd %d: Close\n", _call_fd);
        if (close(_call_fd) == -1) {
            int error = errno;
            errno = 0;
            rawstor_error(
                "Virtq::~Virtq(): Close failed: %s\n", strerror(error));
        }
    }
}


void Virtq::set_call_fd(int fd) {
    if (_call_fd != -1) {
        if (close(_call_fd) == -1) {
            RAWSTOR_THROW_ERRNO();
        }
    }
    _call_fd = fd;
}


}} // rawstor::vhost
