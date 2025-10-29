#ifndef RAWSTOR_VHOST_CLIENT_HPP
#define RAWSTOR_VHOST_CLIENT_HPP

#include <cstdint>

namespace rawstor {
namespace vhost {


class Client final {
    private:
        int _fd;
        int _backend_fd;
        uint64_t _features;

    public:
        explicit Client(int fd):
            _fd(fd),
            _backend_fd(-1),
            _features(0)
        {}
        Client(const Client &) = delete;
        Client(Client &&) = delete;
        ~Client();

        Client& operator=(const Client &) = delete;
        Client& operator=(Client &&) = delete;

        inline int fd() const noexcept {
            return _fd;
        }

        uint64_t get_features() const noexcept {
            return _features;
        }

        void set_features(uint64_t features) noexcept {
            _features = features;
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

#endif // RAWSTOR_VHOST_CLIENT_HPP
