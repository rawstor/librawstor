#ifndef RAWSTOR_VHOST_DEVICE_HPP
#define RAWSTOR_VHOST_DEVICE_HPP

extern "C" {
#include "libvhost-user.h"
}

#include <unordered_map>

#include <cstdint>


struct virtio_blk_config;


namespace rawstor {
namespace vhost {


class Device final {
    private:
        static std::unordered_map<int, Device*> _devices;

        VuDev _dev;
        VuDevIface _iface;
        uint64_t _features;
        uint64_t _protocol_features;
        std::unique_ptr<virtio_blk_config> _blk_config;
        std::unordered_map<int, int> _watches;

    public:
        static Device* get(int fd);

        explicit Device(int fd);
        Device(const Device &) = delete;
        Device(Device &&) = delete;
        ~Device();

        Device& operator=(const Device &) = delete;
        Device& operator=(Device &&) = delete;

        inline VuDev* dev() noexcept {
            return &_dev;
        }

        void dispatch();

        uint64_t get_features() const noexcept {
            return _features;
        }

        void set_features(uint64_t features) noexcept {
            _features = features;
        }

        uint64_t get_protocol_features() const noexcept {
            return _protocol_features;
        }

        void set_protocol_features(uint64_t features) noexcept {
            _protocol_features = features;
        }

        void get_config(uint8_t *config, uint32_t len) const;

        void set_config(
             const uint8_t *data,
             uint32_t offset, uint32_t size, uint32_t flags);

        void set_watch(int fd, int condition, vu_watch_cb cb, void *data);

        void remove_watch(int fd);

        int get_watch(int fd) const noexcept;

        uint64_t get_max_mem_slots() const noexcept {
            /**
             * vhost in the kernel usually supports 509 mem slots. 509 used to
             * be the KVM limit, it supported 512, but 3 were used for internal
             * purposes. This limit is sufficient to support many DIMMs and
             * virtio-mem in "dynamic-memslots" mode.
             */
            return 509;
        }

        /*
        void set_backend_req_fd(int fd) noexcept {
            if (vmsg->fd_num != 1) {
                vu_panic(dev, "Invalid backend_req_fd message (%d fd's)", vmsg->fd_num);
                return false;
            }

            if (dev->backend_fd != -1) {
                close(dev->backend_fd);
            }
            dev->backend_fd = vmsg->fds[0];
            DPRINT("Got backend_fd: %d\n", vmsg->fds[0]);

            return false;
        }
        */

        void loop();
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_DEVICE_HPP
