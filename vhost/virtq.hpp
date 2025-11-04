#ifndef RAWSTOR_VHOST_VIRTQ_HPP
#define RAWSTOR_VHOST_VIRTQ_HPP

namespace rawstor {
namespace vhost {


class Virtq final {
    private:
        int _call_fd;

    public:
        Virtq(): _call_fd(-1) {}
        Virtq(const Virtq &) = delete;
        Virtq(Virtq &&) = delete;
        ~Virtq();

        Virtq& operator=(const Virtq &) = delete;
        Virtq& operator=(Virtq &&) = delete;

        void set_call_fd(int fd);
};


}} // rawstor::vhost

#endif // RAWSTOR_VHOST_VIRTQ_HPP
