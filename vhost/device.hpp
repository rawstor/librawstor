#ifndef RAWSTOR_VHOST_DEVICE_HPP
#define RAWSTOR_VHOST_DEVICE_HPP

#include <rawstor/object.h>

extern "C" {
#include "libvhost-user.h"
}

#include <memory>
#include <string>
#include <unordered_map>

#include <cstdint>

struct virtio_blk_config;

namespace rawstor {
namespace vhost {

class Device;

class Watcher {
private:
    RawstorIOEvent* _event;
    int _counter;

public:
    Watcher(
        rawstor::vhost::Device& device, int fd, int condition, vu_watch_cb cb,
        void* data
    );
    ~Watcher();

    int inc_counter() noexcept { return ++_counter; }
    int dec_counter() noexcept { return --_counter; }
};

class Device final {
private:
    static std::unordered_map<int, Device*> _devices;

    RawstorObjectSpec _spec;
    RawstorObject* _object;

    VuDev _dev;
    VuDevIface _iface;
    uint64_t _features;
    uint64_t _protocol_features;
    std::unique_ptr<virtio_blk_config> _blk_config;
    std::unordered_map<int, std::unique_ptr<Watcher>> _watches;

public:
    static Device& get(int fd);
    static Device* find(int fd);

    Device(const std::string& object_uris, int fd);
    Device(const Device&) = delete;
    Device(Device&&) = delete;
    ~Device();

    Device& operator=(const Device&) = delete;
    Device& operator=(Device&&) = delete;

    inline RawstorObject* object() noexcept { return _object; }

    inline VuDev* dev() noexcept { return &_dev; }

    void dispatch();

    inline uint64_t get_features() const noexcept { return _features; }

    inline void set_features(uint64_t features) noexcept {
        _features = features;
    }

    inline uint64_t get_protocol_features() const noexcept {
        return 1ULL << VHOST_USER_PROTOCOL_F_MQ |
               1ULL << VHOST_USER_PROTOCOL_F_LOG_SHMFD |
               1ULL << VHOST_USER_PROTOCOL_F_BACKEND_REQ |
               1ULL << VHOST_USER_PROTOCOL_F_HOST_NOTIFIER |
               1ULL << VHOST_USER_PROTOCOL_F_BACKEND_SEND_FD |
               1ULL << VHOST_USER_PROTOCOL_F_REPLY_ACK |
               1ULL << VHOST_USER_PROTOCOL_F_CONFIGURE_MEM_SLOTS |
               1ULL << VHOST_USER_PROTOCOL_F_CONFIG | _protocol_features;
    }

    inline void set_protocol_features(uint64_t features) noexcept {
        _protocol_features = features;
    }

    void get_config(uint8_t* config, uint32_t len) const;

    void set_config(
        const uint8_t* data, uint32_t offset, uint32_t size, uint32_t flags
    );

    void set_watch(int fd, int condition, vu_watch_cb cb, void* data);

    void remove_watch(int fd);

    bool has_watch(int fd) const noexcept;

    void loop();
};

} // namespace vhost
} // namespace rawstor

#endif // RAWSTOR_VHOST_DEVICE_HPP
