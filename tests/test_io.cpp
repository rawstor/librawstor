#include "opts.h"
#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>

#include <gtest/gtest.h>

#include <cerrno>
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
        RawstorObjectSpec spec{};
        spec.size = size;
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

    inline RawstorObject* raw() const noexcept { return _object; }

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
        int res = rawstor_object_pwrite(
            _object, buf, size, 0, false, callback, cb.get()
        );
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

    void flush() {
        bool completed = false;
        auto cb = std::make_unique<std::function<void(size_t, int)>>(
            [&completed](size_t, int error) {
                if (error) {
                    RAWSTD_THROW_SYSTEM_ERROR(error);
                }
                completed = true;
            }
        );
        int res = rawstor_object_flush(_object, callback, cb.get());
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
    rawstor::tests::TmpDir dir;
    std::filesystem::path path =
        dir.path() / "00000000-0000-7000-8000-000000000000";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string target = oss.str();

    Queue queue(16);

    Object object(queue, target, 1ull << 20);

    std::string write_data = "ping";
    EXPECT_NO_THROW(object.write(write_data.data(), write_data.length()));

    EXPECT_NO_THROW(object.flush());

    std::string read_data(4, '\0');
    EXPECT_NO_THROW(object.read(read_data.data(), read_data.length()));

    EXPECT_EQ(read_data, "ping");
}

TEST(FileIOTest, flush) {
    rawstor::tests::TmpDir dir;
    std::filesystem::path path =
        dir.path() / "00000000-0000-7000-8000-000000000001";
    std::ostringstream oss;
    oss << "file://" << path.string();
    std::string target = oss.str();

    Queue queue(16);

    Object object(queue, target, 1ull << 20);

    std::string write_data = "ping";
    EXPECT_NO_THROW(object.write(write_data.data(), write_data.length()));
    EXPECT_NO_THROW(object.flush());
}

TEST(OstIOTest, basics) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(RAWSTOR_MAGIC, 1, 4);
        s.cmd_flush(RAWSTOR_MAGIC, 2, 0);
        s.cmd_read(RAWSTOR_MAGIC, 3, "pong", 4);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));

    EXPECT_NO_THROW(object.flush());

    std::string pong(4, '\0');
    EXPECT_NO_THROW(object.read(pong.data(), pong.length()));
    EXPECT_EQ(pong, "pong");
}

TEST(OstIOTest, flush) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(RAWSTOR_MAGIC, 1, 4);
        s.cmd_flush(RAWSTOR_MAGIC, 2, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));
    EXPECT_NO_THROW(object.flush());
}

TEST(OstIOTest, set_object_fail) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
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
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
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
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
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
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(0, 1, 4);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
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
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, -ENOENT);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_THROW(object.write(ping.data(), ping.length()), std::system_error);
}

TEST(OstIOTest, write_busy_retries_without_reconnect) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // A single session handles SET_OBJECT, an EBUSY response to the first
    // WRITE, and a second WRITE that succeeds -- all on the SAME
    // connection. If the retry reconnected instead (like it does for
    // every other error), this session would never see that second WRITE
    // and the test would hang waiting for a connection nothing here
    // accepts.
    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, -EBUSY);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 2, 4);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));
}

TEST(OstIOTest, write_disconnect) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_THROW(object.write(ping.data(), ping.length()), std::system_error);
}

TEST(OstIOTest, write_disconnect_concurrent) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // The object-open session, and each of its retries below, disconnects
    // right after SET_OBJECT succeeds -- before either concurrent write
    // further down is even attempted on it. Both rawstor_object_pwrite()
    // calls below are issued back to back with no rawio_wait_timeout() in
    // between, so Session::_add_op() runs for both before the client's
    // event loop has had any chance to deliver either op's own request
    // send completion. This is the window a stranded op used to fall
    // into: registered in Session::_ops, but not yet "in flight" by
    // SessionOp::in_flight()'s old (now removed) definition.
    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    bool done1 = false;
    bool done2 = false;
    int err1 = 0;
    int err2 = 0;
    auto cb1 = std::make_unique<std::function<void(size_t, int)>>(
        [&done1, &err1](size_t, int error) {
            done1 = true;
            err1 = error;
        }
    );
    auto cb2 = std::make_unique<std::function<void(size_t, int)>>(
        [&done2, &err2](size_t, int error) {
            done2 = true;
            err2 = error;
        }
    );

    std::string ping = "ping";
    std::string pong = "pong";

    int res = rawstor_object_pwrite(
        object.raw(), ping.data(), ping.length(), 0, false, callback, cb1.get()
    );
    ASSERT_GE(res, 0);
    cb1.release();

    res = rawstor_object_pwrite(
        object.raw(), pong.data(), pong.length(), 4, false, callback, cb2.get()
    );
    ASSERT_GE(res, 0);
    cb2.release();

    // A bounded, timeout-based pump rather than the blocking
    // Object::write() helper: an orphaned op would otherwise hang this
    // loop -- and the whole test binary -- forever instead of failing
    // the test. A write whose send() happens to succeed against an
    // already-dead connection (a real possibility: the RST from the
    // server closing early can still be in flight when the client's own
    // send() call goes out, so the kernel briefly accepts the data) has
    // no way to fail until TCP_USER_TIMEOUT gives up on it -- so this
    // budget must comfortably exceed rawstor_opts_tcp_user_timeout(), or
    // this loop can lose that race and fail the test even though the op
    // would have completed a moment later.
    unsigned int budget_ms = rawstor_opts_tcp_user_timeout() + 5000;
    for (unsigned int elapsed_ms = 0;
         elapsed_ms < budget_ms && !(done1 && done2); elapsed_ms += 100) {
        int wres = rawio_wait_timeout(queue, 100);
        if (wres < 0 && wres != -ETIME) {
            break;
        }
    }

    EXPECT_TRUE(done1) << "first write orphaned (never completed)";
    EXPECT_TRUE(done2) << "second write orphaned (never completed)";
    EXPECT_NE(err1, 0);
    EXPECT_NE(err2, 0);
}

TEST(OstIOTest, snapshot_read_only) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);

    /*
     * A two-member snapshot target with the second member down: an
     * immutable snapshot version needs no quorum — one reachable member
     * serves reads, and the mirror state machine is bypassed (no
     * metadata compare, no barriers).
     */
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000@5"
        ",ost://127.0.0.1:8754/00000000-0000-7000-8000-000000000000@5";

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_read(RAWSTOR_MAGIC, 1, "snap", 4);
    }

    RawstorObject* object = nullptr;
    ASSERT_EQ(rawstor_object_open(queue, target.c_str(), &object), 0);

    {
        char buf[4] = {};
        bool completed = false;
        auto cb = std::make_unique<std::function<void(size_t, int)>>(
            [&completed](size_t result, int error) {
                EXPECT_EQ(error, 0);
                EXPECT_EQ(result, 4u);
                completed = true;
            }
        );
        ASSERT_EQ(
            rawstor_object_pread(
                object, buf, sizeof(buf), 0, callback, cb.get()
            ),
            0
        );
        cb.release();
        while (!completed) {
            queue.wait();
        }
        EXPECT_EQ(memcmp(buf, "snap", 4), 0);
    }

    {
        /* Writes to an immutable version fail without touching the wire. */
        char buf[4] = {};
        bool completed = false;
        int write_error = 0;
        auto cb = std::make_unique<std::function<void(size_t, int)>>(
            [&completed, &write_error](size_t, int error) {
                write_error = error;
                completed = true;
            }
        );
        ASSERT_EQ(
            rawstor_object_pwrite(
                object, buf, sizeof(buf), 0, /*sync=*/false, callback, cb.get()
            ),
            0
        );
        cb.release();
        while (!completed) {
            queue.wait();
        }
        EXPECT_EQ(write_error, EROFS);
    }

    EXPECT_EQ(rawstor_object_close(object), 0);
}

} // unnamed namespace
