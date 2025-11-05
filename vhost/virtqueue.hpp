#ifndef RAWSTOR_VHOST_VIRTQUEUE_HPP
#define RAWSTOR_VHOST_VIRTQUEUE_HPP

namespace rawstor {
namespace vhost {


class VirtQueue final {
    private:
        int _call_fd;
        int _err_fd;

    public:
        VirtQueue():
            _call_fd(-1),
            _err_fd(-1)
        {}
        VirtQueue(const VirtQueue &) = delete;
        VirtQueue(VirtQueue &&) = delete;
        ~VirtQueue();

        VirtQueue& operator=(const VirtQueue &) = delete;
        VirtQueue& operator=(VirtQueue &&) = delete;

        void set_call_fd(int fd);

        void set_err_fd(int fd);
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_VIRTQUEUE_HPP
