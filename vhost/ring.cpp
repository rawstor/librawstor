#include "ring.hpp"

#include "device.hpp"

#include <rawstd/logging.h>

#include <stdexcept>

namespace rawstor {
namespace vhost {

void Ring::set_addr(
    const AddressTranslator& translate, const vhost_vring_addr& vra
) {
    _flags = vra.flags;
    _log_guest_addr = vra.log_guest_addr;

    _desc = static_cast<vring_desc*>(translate(vra.desc_user_addr));
    _used = static_cast<vring_used*>(translate(vra.used_user_addr));
    _avail = static_cast<vring_avail*>(translate(vra.avail_user_addr));

    rawstd_debug("Setting virtq addresses:\n");
    rawstd_debug("    vring_desc  at %p\n", (void*)_desc);
    rawstd_debug("    vring_used  at %p\n", (void*)_used);
    rawstd_debug("    vring_avail at %p\n", (void*)_avail);

    if (!(_desc && _used && _avail)) {
        throw std::runtime_error("Invalid vring_addr message");
    }
}

void Ring::set_addr(const Device& device, const vhost_vring_addr& vra) {
    set_addr(
        [&device](uint64_t addr) { return device.userspace_va_to_va(addr); },
        vra
    );
}

} // namespace vhost
} // namespace rawstor
