#include "server.hpp"

#include "device.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor.h>

#include <string>

namespace rawstor {
namespace vduse {

Server::Server(
    unsigned int queue_size, const std::string& target, const std::string& name,
    bool write_cache_enabled
) :
    _queue_size(queue_size),
    _target(target),
    _name(name),
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
    rawstd_info("Creating VDUSE device %s\n", _name.c_str());

    Device d(_queue_size, _target, _name, _write_cache_enabled);
    d.loop();
}

} // namespace vduse
} // namespace rawstor
