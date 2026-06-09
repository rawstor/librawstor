#include "backend.hpp"
#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/ost_protocol.h>

#include <gtest/gtest.h>

#include <cstring>
#include <functional>
#include <memory>

namespace {

int callback(RawstorObject*, size_t, size_t result, int error, void* data) {
    std::shared_ptr<std::function<void(size_t, int)>> cb(
        static_cast<std::function<void(size_t, int)>*>(data)
    );
    try {
        (*cb)(result, error);
        return 0;
    } catch (const std::system_error& e) {
        return -e.code().value();
    } catch (const std::exception& e) {
        rawstd_error("Unexpected error: %s\n", e.what());
        return -EINVAL;
    } catch (...) {
        rawstd_error("Unexpected error\n");
        return -EINVAL;
    }
}

class IOTest
    : public testing::TestWithParam<std::shared_ptr<rawstor::tests::Backend>> {
protected:
    std::shared_ptr<rawstor::tests::Backend> _backend;

    void SetUp() override { _backend = GetParam(); }
};

class Queue {
private:
    RawIOQueue* _queue;

public:
    Queue(unsigned int size) : _queue(nullptr) {
        int res = rawio_queue_create(size, &_queue);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
    Queue(const Queue&) = delete;
    Queue(Queue&&) = delete;

    ~Queue() { rawio_queue_delete(_queue); }

    Queue& operator=(const Queue&) = delete;
    Queue& operator=(Queue&&) = delete;
    operator RawIOQueue*() noexcept { return _queue; }
};

class Object {
private:
    std::shared_ptr<rawstor::tests::Backend> _backend;
    Queue& _queue;
    std::string _target;
    RawstorObject* _object;

public:
    explicit Object(
        std::shared_ptr<rawstor::tests::Backend> backend, Queue& queue,
        size_t size
    ) :
        _backend(backend),
        _queue(queue),
        _target(1024, '\0'),
        _object(nullptr) {
        _backend->accept();
        RawstorObjectSpec spec{.size = size};
        int res = rawstor_object_create(
            _backend->uris().c_str(), &spec, _target.data(), _target.length()
        );
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        _backend->close();
    }

    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object() {
        close();
        if (_backend->protocol() != "ost") {
            _backend->accept();
            rawstor_object_remove(_target.c_str());
            _backend->close();
        }
    }

    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;
    operator RawstorObject*() noexcept { return _object; }

    inline const std::string& target() const noexcept { return _target; }

    void open() {
        int res = rawstor_object_open(_queue, _target.c_str(), &_object);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }

    void close() {
        if (_object != nullptr) {
            int res = rawstor_object_close(_object);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
            _object = nullptr;
        }
    }
};

TEST_P(IOTest, readwrite) {
    Queue q(16);

    Object o(_backend, q, 1ull << 20);

    RawstorOSTFrameBasic basic;
    RawstorOSTFrameResponse response = {
        .head{
            .magic = 0,
            .cmd = 0,
            .cid = 0,
        },
        .body = {
            .res = 0,
            .hash = 0,
        },
    };
    _backend->accept();
    _backend->read(&basic, sizeof(basic));
    _backend->write(&response, sizeof(response));
    _backend->close();

    o.open();

    const char data[] = "hello world";
    auto cb =
        std::make_shared<std::function<void(size_t, int)>>([](size_t, int) {
            printf("HERE\n");
        });
    rawstor_object_pwrite(o, data, sizeof(data) - 1, 0, callback, cb.get());

    o.close();
}

INSTANTIATE_TEST_SUITE_P(
    AllBackends, IOTest, ::testing::ValuesIn(rawstor::tests::backends),
    [](const ::testing::TestParamInfo<std::shared_ptr<rawstor::tests::Backend>>&
           info) { return info.param->protocol(); }
);

} // unnamed namespace
