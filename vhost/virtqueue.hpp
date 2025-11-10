#ifndef RAWSTOR_VHOST_VIRTQUEUE_HPP
#define RAWSTOR_VHOST_VIRTQUEUE_HPP

namespace rawstor {
namespace vhost {


class VirtQueue final {
    private:
        bool _enabled;
        int _call_fd;
        int _err_fd;
        int _vring_size;

    public:
        VirtQueue():
            _enabled(false),
            _call_fd(-1),
            _err_fd(-1)
        {}
        VirtQueue(const VirtQueue &) = delete;
        VirtQueue(VirtQueue &&) = delete;
        ~VirtQueue();

        VirtQueue& operator=(const VirtQueue &) = delete;
        VirtQueue& operator=(VirtQueue &&) = delete;

        inline void enable() noexcept {
            _enabled = true;
        }

        inline void disable() noexcept {
            _enabled = false;
        }

        void set_vring_size(unsigned int size) {
            _vring_size = size;
        }

        void set_call_fd(int fd);

        void set_err_fd(int fd);
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_VIRTQUEUE_HPP
