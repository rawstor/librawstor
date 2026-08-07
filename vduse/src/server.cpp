#include "server.hpp"

#include "device.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor.h>

#include <string>

namespace rawstor {
namespace vduse {

Server::Server(
    unsigned int queue_size, const std::string& target, bool write_cache_enabled
) :
    _queue_size(queue_size),
    _target(target),
    _write_cache_enabled(write_cache_enabled) {
    int res = rawstor_initialize(NULL);
    if (res) {
        RAWSTD_THROW_SYSTEM_ERROR(-res);
    }
}

Server::~Server() {
    rawstor_terminate();
}

void Server::loop() {
    // Device's constructor logs the resolved VDUSE device name (the
    // target object's UUID) once it's known.
    Device d(_queue_size, _target, _write_cache_enabled);
    d.loop();
}

} // namespace vduse
} // namespace rawstor
