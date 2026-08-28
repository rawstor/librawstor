#include <vduse/ring.hpp>

#include <rawstd/logging.h>

#include <stdexcept>

namespace rawstor {
namespace vduse {

void Ring::set_addr(
    const AddressTranslator& translate, uint64_t desc_addr,
    uint64_t driver_addr, uint64_t device_addr
) {
    _desc_addr = desc_addr;
    _driver_addr = driver_addr;
    _device_addr = device_addr;

    _desc = static_cast<vring_desc*>(translate(desc_addr));
    _avail = static_cast<vring_avail*>(translate(driver_addr));
    _used = static_cast<vring_used*>(translate(device_addr));

    rawstd_debug("Setting virtq addresses:\n");
    rawstd_debug("    vring_desc  at %p\n", (void*)_desc);
    rawstd_debug("    vring_avail at %p\n", (void*)_avail);
    rawstd_debug("    vring_used  at %p\n", (void*)_used);

    if (!(_desc && _avail && _used)) {
        throw std::runtime_error("Invalid virtqueue addresses");
    }
}

} // namespace vduse
} // namespace rawstor
