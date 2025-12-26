#include "ring.hpp"

#include "device.hpp"

#include <rawstorstd/logging.h>

#include <stdexcept>


namespace rawstor {
namespace vhost {


void Ring::set_addr(const Device &device, const vhost_vring_addr &vra) {
    _flags = vra.flags;
    _log_guest_addr = vra.log_guest_addr;

    _desc = static_cast<vring_desc*>(
        device.userspace_va_to_va(vra.desc_user_addr));
    _used = static_cast<vring_used*>(
        device.userspace_va_to_va(vra.used_user_addr));
    _avail = static_cast<vring_avail*>(
        device.userspace_va_to_va(vra.avail_user_addr));

    rawstor_debug("Setting virtq addresses:\n");
    rawstor_debug("    vring_desc  at %p\n", _desc);
    rawstor_debug("    vring_used  at %p\n", _used);
    rawstor_debug("    vring_avail at %p\n", _avail);

    if (!(_desc && _used && _avail)) {
        throw std::runtime_error("Invalid vring_addr message");
    }
}


}} // rawstor::vhost
