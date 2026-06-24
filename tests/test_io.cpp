#include "server.hpp"
#include "session.hpp"

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
        int res = rawio_wait(_queue);
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
    Object(Queue& queue, const std::string& target, size_t size) :
        _queue(queue),
        _target(target),
        _object(nullptr) {
        RawstorObjectSpec spec{.size = size};
        int res = rawstor_object_create(target.c_str(), &spec);
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }

        try {
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
        int res =
            rawstor_object_pread(_object, buf, size, 0, callback, cb.get());
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        cb.release();

        while (!completed) {
            try {
                _queue.wait();
            } catch (...) {
                if (!completed) {
                    throw;
                }
            }
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
        int res =
            rawstor_object_pwrite(_object, buf, size, 0, callback, cb.get());
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR(-res);
        }
        cb.release();

        while (!completed) {
            try {
                _queue.wait();
            } catch (...) {
                if (!completed) {
                    throw;
                }
            }
        }
    }
};

TEST(FileIOTest, basics) {
    std::filesystem::path path = std::filesystem::temp_directory_path() /
                                 "test_objects" /
                                 "00000000-0000-7000-8000-000000000000";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string target = oss.str();

    Queue queue(16);

    Object object(queue, target, 1ull << 20);

    std::string write_data = "ping";
    EXPECT_NO_THROW(object.write(write_data.data(), write_data.length()));

    std::string read_data(4, '\0');
    EXPECT_NO_THROW(object.read(read_data.data(), read_data.length()));

    EXPECT_EQ(read_data, "ping");
}

TEST(OstIOTest, basics) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(RAWSTOR_MAGIC, 1, 4);
        s.cmd_read(RAWSTOR_MAGIC, 2, "pong", 4);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));

    std::string pong(4, '\0');
    EXPECT_NO_THROW(object.read(pong.data(), pong.length()));
    EXPECT_EQ(pong, "pong");
}

TEST(OstIOTest, set_object_fail) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(0, 0, 0);
    }

    EXPECT_THROW(
        { Object object(queue, target, 1ull << 20); }, std::system_error
    );
}

TEST(OstIOTest, set_object_error) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, -ENOENT);
    }

    EXPECT_THROW(
        { Object object(queue, target, 1ull << 20); }, std::system_error
    );
}

TEST(OstIOTest, set_object_disconnect) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
    }

    EXPECT_THROW(
        { Object object(queue, target, 1ull << 20); }, std::system_error
    );
}

TEST(OstIOTest, write_fail) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(0, 1, 4);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_THROW(object.write(ping.data(), ping.length()), std::system_error);
}

TEST(OstIOTest, write_error) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, -ENOENT);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_THROW(object.write(ping.data(), ping.length()), std::system_error);
}

TEST(OstIOTest, write_disconnect) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate();
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_THROW(object.write(ping.data(), ping.length()), std::system_error);
}

} // unnamed namespace
