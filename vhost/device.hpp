#ifndef RAWSTOR_VHOST_DEVICE_HPP
#define RAWSTOR_VHOST_DEVICE_HPP

#include "protocol.h"
#include "virtqueue.hpp"

#include <rawstorstd/gpp.hpp>

#include <unistd.h>

#include <vector>

#include <cstdint>


namespace rawstor {
namespace vhost {


class Device final {
    private:
        int _fd;
        int _backend_fd;
        uint64_t _features;
        uint64_t _protocol_features;
        std::vector<VirtQueue> _vqs;
        VirtioBlkConfig _config;

    public:
        explicit Device(int fd):
            _fd(fd),
            _backend_fd(-1),
            _features(0),
            _protocol_features(0),
            _vqs(1),
            _config{}
        {}
        Device(const Device &) = delete;
        Device(Device &&) = delete;
        ~Device();

        Device& operator=(const Device &) = delete;
        Device& operator=(Device &&) = delete;

        inline int fd() const noexcept {
            return _fd;
        }

        uint64_t get_features() const noexcept;

        void set_features(uint64_t features);

        uint64_t get_protocol_features() const noexcept;

        void set_protocol_features(uint64_t features) noexcept {
            _protocol_features = features;
        }

        void set_backend_fd(int fd) {
            if (_backend_fd != -1) {
                if (close(_backend_fd)) {
                    RAWSTOR_THROW_ERRNO();
                }
            }
            _backend_fd = fd;
        }

        inline size_t nqueues() const noexcept {
            return _vqs.size();
        }

        void set_vring_call(size_t index, int fd);

        void set_vring_err(size_t index, int fd);

        const VirtioBlkConfig& get_config() const noexcept {
            return _config;
        }

        uint64_t get_max_mem_slots() const noexcept {
            /**
             * vhost in the kernel usually supports 509 mem slots. 509 used to
             * be the KVM limit, it supported 512, but 3 were used for internal
             * purposes. This limit is sufficient to support many DIMMs and
             * virtio-mem in "dynamic-memslots" mode.
             */
            return 509;
        }

        void loop();
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_DEVICE_HPP
