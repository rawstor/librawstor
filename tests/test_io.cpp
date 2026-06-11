#include "server.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/ost_protocol.h>

#include <gtest/gtest.h>

#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>

namespace {

int callback(RawstorObject*, size_t, size_t result, int error, void* data) {
    std::unique_ptr<std::function<void(size_t, int)>> cb(
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

    void wait() {
        int res = rawio_wait_timeout(_queue, 0);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
    }
};

class Object {
private:
    Queue& _queue;
    std::string _target;
    RawstorObject* _object;

    void _close() {
        if (_object != nullptr) {
            int res = rawstor_object_close(_object);
            if (res < 0) {
                rawstd_error("%s\n", strerror(-res));
            }
            _object = nullptr;
        }
    }

public:
    Object(Queue& queue, const std::string& location, size_t size) :
        _queue(queue),
        _target(1024, '\0'),
        _object(nullptr) {
        RawstorObjectSpec spec{.size = size};
        int res = rawstor_object_create(
            location.c_str(), &spec, _target.data(), _target.size()
        );
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        try {
            _target.resize(res);
            res = rawstor_object_open(_queue, _target.c_str(), &_object);
            if (res < 0) {
                RAWSTD_THROW_SYSTEM_ERROR(-res);
            }
        } catch (...) {
            _close();
            throw;
        }
    }

    Object(const Object&) = delete;
    Object(Object&&) = delete;
    ~Object() {
        _close();
        rawstor_object_remove(_target.c_str());
    }

    Object& operator=(const Object&) = delete;
    Object& operator=(Object&&) = delete;

    inline const std::string& target() const noexcept { return _target; }

    void read(void* buf, size_t size) {
        bool completed = false;
        auto cb = std::make_unique<std::function<void(size_t, int)>>(
            [&completed, &size](size_t result, int error) {
                if (error) {
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                }
                if (result != size) {
                    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
                }
                completed = true;
            }
        );
        rawstor_object_pread(_object, buf, size, 0, callback, cb.get());
        cb.release();

        while (!completed) {
            _queue.wait();
        }
    }

    void write(const void* buf, size_t size) {
        bool completed = false;
        auto cb = std::make_unique<std::function<void(size_t, int)>>(
            [&completed, &size](size_t result, int error) {
                if (error) {
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                }
                if (result != size) {
                    RAWSTD_THROW_SYSTEM_ERROR(EPROTO);
                }
                completed = true;
            }
        );
        rawstor_object_pwrite(_object, buf, size, 0, callback, cb.get());
        cb.release();

        while (!completed) {
            _queue.wait();
        }
    }
};

TEST(FileIOTest, basics) {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() / "test_objects";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string location = oss.str();

    Queue queue(16);

    Object object(queue, location, 1ull << 20);

    std::string write_data = "ping";
    EXPECT_NO_THROW(object.write(write_data.data(), write_data.length()));

    std::string read_data(4, '\0');
    EXPECT_NO_THROW(object.read(read_data.data(), read_data.length()));

    EXPECT_EQ(read_data, "ping");
}

TEST(OstIOTest, basics) {
    Queue queue(16);
    rawstor::tests::Server server(8753);
    std::string location = "ost://127.0.0.1:8753";

    // create object
    server.accept();
    server.close();

    // set object
    server.accept();
    RawstorOSTFrameResponse set_object_response = {
        .head{
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = 0,
        },
        .body = {
            .res = 0,
            .hash = 0,
        },
    };
    server.write(&set_object_response, sizeof(set_object_response));

    Object object(queue, location, 1ull << 20);

    // write
    RawstorOSTFrameResponse write_response = {
        .head{
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_WRITE,
            .cid = 1,
        },
        .body = {
            .res = 4,
            .hash = 0,
        },
    };
    server.write(&write_response, sizeof(write_response));

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));

    // read
    std::string read_response_data = "pong";
    RawstorOSTFrameResponse read_response = {
        .head{
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_READ,
            .cid = 2,
        },
        .body = {
            .res = static_cast<int32_t>(read_response_data.length()),
            .hash = rawstd_hash_scalar(
                read_response_data.data(), read_response_data.length()
            ),
        },
    };
    iovec iov[2] = {
        {
            .iov_base = &read_response,
            .iov_len = sizeof(read_response),
        },
        {
            .iov_base = read_response_data.data(),
            .iov_len = read_response_data.length(),
        },
    };
    server.writev(iov, sizeof(iov) / sizeof(iov[0]));

    std::string pong(4, '\0');
    EXPECT_NO_THROW(object.read(pong.data(), pong.length()));
    EXPECT_EQ(pong, "pong");

    server.close();

    // remove object
    // server.accept();
    // server.close();

    server.wait();
}

TEST(OstIOTest, set_object_fail) {
    Queue queue(16);
    rawstor::tests::Server server(8753);
    std::string location = "ost://127.0.0.1:8753";

    // create object
    server.accept();
    server.close();

    // set object
    RawstorOSTFrameResponse set_object_response = {
        .head{
            .magic = 0, // wrong magic number
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = 0,
        },
        .body = {
            .res = 0,
            .hash = 0,
        },
    };
    for (unsigned int i = 0; i < 3; ++i) {
        server.accept();
        server.write(&set_object_response, sizeof(set_object_response));
        server.close();
    }

    // remove object
    // server.accept();
    // server.close();

    EXPECT_THROW(
        { Object object(queue, location, 1ull << 20); }, std::system_error
    );

    server.wait();
}

TEST(OstIOTest, set_object_error) {
    Queue queue(16);
    rawstor::tests::Server server(8753);
    std::string location = "ost://127.0.0.1:8753";

    // create object
    server.accept();
    server.close();

    // set object
    RawstorOSTFrameResponse set_object_response = {
        .head{
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = 0,
        },
        .body = {
            .res = -ENOENT,
            .hash = 0,
        },
    };
    for (unsigned int i = 0; i < 3; ++i) {
        server.accept();
        server.write(&set_object_response, sizeof(set_object_response));
        server.close();
    }

    // remove object
    // server.accept();
    // server.close();

    EXPECT_THROW(
        { Object object(queue, location, 1ull << 20); }, std::system_error
    );

    server.wait();
}

TEST(OstIOTest, set_object_disconnect) {
    Queue queue(16);
    rawstor::tests::Server server(8753);
    std::string location = "ost://127.0.0.1:8753";

    // create object
    server.accept();
    server.close();

    // set object
    for (unsigned int i = 0; i < 3; ++i) {
        server.accept();
        server.close();
    }

    // remove object
    // server.accept();
    // server.close();

    EXPECT_THROW(
        { Object object(queue, location, 1ull << 20); }, std::system_error
    );

    server.wait();
}

} // unnamed namespace
