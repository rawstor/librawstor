#include "device.hpp"

extern "C" {
#include "libvhost-user.h"
#include "standard-headers/linux/virtio_blk.h"
}

#include <rawstorstd/gpp.hpp>
#include <rawstorstd/logging.h>

#include <rawstor.h>

#include <sys/socket.h>
#include <sys/un.h>

#include <err.h>
#include <errno.h>
#include <inttypes.h>
#include <poll.h>
#include <unistd.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>

#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>


namespace {


class Task {
    protected:
        rawstor::vhost::Device &_device;

    public:
        static int callback(size_t result, int error, void *data) {
            std::unique_ptr<Task> t(static_cast<Task*>(data));
            try {
                (*t)(result, error);
                return 0;
            } catch (std::system_error &e) {
                return -e.code().value();
            }
        }

        Task(rawstor::vhost::Device &device): _device(device) {}
        Task(const Task &) = delete;
        Task(Task &&) = delete;
        virtual ~Task() = default;

        Task& operator=(const Task &) = delete;
        Task& operator=(Task &&) = delete;

        virtual void operator()(size_t result, int error) = 0;
};


class TaskPoll: public Task {
    public:
        TaskPoll(rawstor::vhost::Device &device):
            Task(device)
        {}
        virtual ~TaskPoll() override = default;

        virtual unsigned int mask() = 0;
};


void poll(int fd, std::unique_ptr<TaskPoll> t) {
    int res = rawstor_fd_poll(
        fd, t->mask(),
        t->callback, t.get());
    if (res) {
        RAWSTOR_THROW_SYSTEM_ERROR(-res);
    }
    t.release();
}


class TaskDispatch final: public TaskPoll {
    public:
        TaskDispatch(rawstor::vhost::Device &device):
            TaskPoll(device)
        {}

        unsigned int mask() override {
            return POLLIN;
        }

        void operator()(size_t, int error) override;
};


class TaskWatch final: public TaskPoll {
    private:
        int _fd;
        int _condition;
        int _mask;
        vu_watch_cb _cb;
        void *_data;

    public:
        TaskWatch(
            rawstor::vhost::Device &device,
            int fd, int condition, vu_watch_cb cb, void *data):
            TaskPoll(device),
            _fd(fd),
            _condition(condition),
            _mask(0),
            _cb(cb),
            _data(data)
        {
            if (_condition & VU_WATCH_IN) {
                _mask |= POLLIN;
            }
            if (_condition & VU_WATCH_OUT) {
                _mask |= POLLOUT;
            }
        }

        unsigned int mask() override {
            return _mask;
        }

        void operator()(size_t, int error) override;
};


void TaskDispatch::operator()(size_t result, int error) {
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (!(result & POLLIN)) {
        // TODO: Throw error here
    }

    _device.dispatch();

    std::unique_ptr<TaskDispatch> t =
        std::make_unique<TaskDispatch>(_device);
    poll(_device.dev()->sock, std::move(t));
}


void TaskWatch::operator()(size_t result, int error) {
    if (error != 0) {
        RAWSTOR_THROW_SYSTEM_ERROR(error);
    }

    if (!(result & _mask)) {
        // TODO: Throw error here
    }

    if (_device.get_watch(_fd)) {
        _cb(_device.dev(), _condition, _data);

        std::unique_ptr<TaskWatch> t =
            std::make_unique<TaskWatch>(_device, _fd, _condition, _cb, _data);
        poll(_fd, std::move(t));
    }
}


void panic(VuDev *, const char *err) {
    rawstor_error("libvhost-user: %s\n", err);
}

void set_watch(VuDev *dev, int fd, int condition, vu_watch_cb cb, void *data) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    d->set_watch(fd, condition, cb, data);
}

void remove_watch(VuDev *dev, int fd) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    d->remove_watch(fd);
}


uint64_t get_features(VuDev *dev) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    return d->get_features();
}


void set_features(VuDev *dev, uint64_t features) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    d->set_features(features);
}


uint64_t get_protocol_features(VuDev *dev) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    return d->get_protocol_features();
}


void set_protocol_features(VuDev *dev, uint64_t features) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    d->set_protocol_features(features);
}


int get_config(VuDev *dev, uint8_t *config, uint32_t len) {
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    try {
        d->get_config(config, len);
        return 0;
    } catch (const std::exception &e) {
        rawstor_error("%s\n", e.what());
        return -1;
    }
}


int set_config(
    VuDev *dev, const uint8_t *data,
    uint32_t offset, uint32_t size, uint32_t flags)
{
    rawstor::vhost::Device *d = rawstor::vhost::Device::get(dev->sock);
    try {
        d->set_config(data, offset, size, flags);
        return 0;
    } catch (const std::exception &e) {
        rawstor_error("%s\n", e.what());
        return -1;
    }
}


} // unnamed

namespace rawstor {
namespace vhost {


std::unordered_map<int, Device*> Device::_devices;


Device::Device(const std::string &object_uris, int fd):
    _iface {
        .get_features = ::get_features,
        .set_features = ::set_features, // not required
        .get_protocol_features = ::get_protocol_features,
        .set_protocol_features = ::set_protocol_features,
        .process_msg = nullptr,
        .queue_set_started = nullptr, // implement
        .queue_is_processed_in_order = nullptr,
        .get_config = ::get_config,
        .set_config = ::set_config,
        .get_shared_object = nullptr,
    },
    _features(
        VIRTIO_BLK_F_SIZE_MAX |
        VIRTIO_BLK_F_SEG_MAX |
        VIRTIO_BLK_F_BLK_SIZE |
        VIRTIO_BLK_F_TOPOLOGY |
        VIRTIO_BLK_F_MQ |
        // VIRTIO_BLK_F_FLUSH |
        // VIRTIO_BLK_F_DISCARD |
        // VIRTIO_BLK_F_WRITE_ZEROES |
        VIRTIO_BLK_F_CONFIG_WCE
    ),
    _blk_config(std::make_unique<virtio_blk_config>())
{
    memset(_blk_config.get(), 0, sizeof(*_blk_config.get()));

    int ires = rawstor_object_spec(object_uris.c_str(), &_spec);
    if (ires) {
        RAWSTOR_THROW_SYSTEM_ERROR(-ires);
    }

    _blk_config->capacity = _spec.size >> 9;

    _blk_config->size_max = 1 << 16; // VIRTIO_BLK_F_SIZE_MAX

    _blk_config->seg_max = 1 << 7 - 2; // VIRTIO_BLK_F_SEG_MAX

    _blk_config->geometry = { // VIRTIO_BLK_F_GEOMETRY
        .cylinders = 0,
        .heads = 0,
        .sectors = 0,
    };

    _blk_config->blk_size = 1 << 9; // VIRTIO_BLK_F_BLK_SIZE

	_blk_config->physical_block_exp = 0; // VIRTIO_BLK_F_TOPOLOGY
	_blk_config->alignment_offset = 0; // VIRTIO_BLK_F_TOPOLOGY
	_blk_config->min_io_size = 1; // VIRTIO_BLK_F_TOPOLOGY
	_blk_config->opt_io_size = 1; // VIRTIO_BLK_F_TOPOLOGY

	_blk_config->wce = 0; // VIRTIO_BLK_F_CONFIG_WCE

	_blk_config->num_queues = 1; // VIRTIO_BLK_F_MQ

	_blk_config->max_discard_sectors = 0; // VIRTIO_BLK_F_DISCARD
	_blk_config->max_discard_seg = 0; // VIRTIO_BLK_F_DISCARD
	_blk_config->discard_sector_alignment = 0; // VIRTIO_BLK_F_DISCARD

	_blk_config->max_write_zeroes_sectors = 0; // VIRTIO_BLK_F_WRITE_ZEROES
	_blk_config->max_write_zeroes_seg = 0; // VIRTIO_BLK_F_WRITE_ZEROES
	_blk_config->write_zeroes_may_unmap = 0; // VIRTIO_BLK_F_WRITE_ZEROES

	_blk_config->max_secure_erase_sectors = 0; // VIRTIO_BLK_F_SECURE_ERASE
	_blk_config->max_secure_erase_seg = 0; // VIRTIO_BLK_F_SECURE_ERASE
	_blk_config->secure_erase_sector_alignment = 0; // VIRTIO_BLK_F_SECURE_ERASE

    _blk_config->zoned = { // VIRTIO_BLK_F_ZONED
        .zone_sectors = 0,
        .max_open_zones = 0,
        .max_active_zones = 0,
        .max_append_sectors = 0,
        .write_granularity = 0,
        .model = 0,
    };

    bool bres = vu_init(
        &_dev, 1, fd, panic, nullptr, ::set_watch, ::remove_watch, &_iface);
    assert(bres == true);

    _devices.insert(std::pair<int, Device*>(fd, this));
}


Device::~Device() {
    _devices.erase(_dev.sock);
    vu_deinit(&_dev);
}


Device* Device::get(int fd) {
    return _devices.at(fd);
}


void Device::dispatch() {
    bool res = vu_dispatch(&_dev);
    assert(res == true);
}


void Device::get_config(uint8_t *config, uint32_t len) const {
    if (len > sizeof(virtio_blk_config)) {
        std::ostringstream oss;
        oss << "virtio_blk_config struct is smaller than expected: "
            << sizeof(virtio_blk_config) << " < " << len;
        throw std::runtime_error(oss.str());
    }

    memcpy(config, _blk_config.get(), len);
}


void Device::set_config(
    const uint8_t *data,
    uint32_t offset, uint32_t size, uint32_t flags)
{
    /* don't support live migration */
    if (flags != VHOST_SET_CONFIG_TYPE_FRONTEND) {
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (offset != offsetof(virtio_blk_config, wce)) {
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    if (size != 1) {
        RAWSTOR_THROW_SYSTEM_ERROR(EINVAL);
    }

    _blk_config->wce = *data;
}


void Device::set_watch(int fd, int condition, vu_watch_cb cb, void *data) {
    _watches.insert(std::pair<int, int>(fd, condition));
    std::unique_ptr<TaskWatch> t =
        std::make_unique<TaskWatch>(*this, fd, condition, cb, data);
    poll(fd, std::move(t));
}


void Device::remove_watch(int fd) {
    _watches.erase(fd);
}


int Device::get_watch(int fd) const noexcept {
    const auto &it = _watches.find(fd);
    if (it == _watches.end()) {
        return 0;
    }
    return it->second;
}


void Device::loop() {
    std::unique_ptr<TaskDispatch> t =
        std::make_unique<TaskDispatch>(*this);
    poll(_dev.sock, std::move(t));

    while (!rawstor_empty()) {
        int res = rawstor_wait();
        if (res) {
            if (res == -ETIME) {
                rawstor_warning("rawstor_wait() failed: timeout\n");
                continue;
            }

            RAWSTOR_THROW_SYSTEM_ERROR(-res);
        }
    }
}


}} // rawstor::vhost
