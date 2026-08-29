#include "opts.h"
#include "rawio_sync.hpp"
#include "server.hpp"
#include "session.hpp"
#include "tmp_dir.hpp"

#include <rawstd/gpp.hpp>
#include <rawstd/hash.h>
#include <rawstd/logging.h>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/target.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <cstring>
#include <filesystem>
#include <functional>
#include <memory>

namespace {

int callback(size_t result, int error, void* data) {
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

// Used by Object's close (in _close()): rawstor_object_close()'s
// ssize_t result callback shape (negative -> -errno, zero -> success)
// has nothing else to report.
struct Result {
    int error = 0;
    bool done = false;
};

int result_cb(ssize_t result, void* data) {
    Result* r = static_cast<Result*>(data);
    r->error = result < 0 ? static_cast<int>(-result) : 0;
    r->done = true;
    return 0;
}

// Overrides rawstor_opts_io_attempts()/io_wire_retry_attempts() for the
// lifetime of one test, to prove they're independent budgets -- see
// Connection::_with_retry(). Restores the library's normal opts (env
// vars/compiled-in defaults) on scope exit, same as
// ThrottleOptsOverride in test_blk_session.cpp/test_object.cpp.
class WireRetryOptsOverride final {
public:
    WireRetryOptsOverride(
        unsigned int io_attempts, unsigned int io_wire_retry_attempts
    ) {
        RawstorOpts opts{};
        opts.io_attempts = io_attempts;
        opts.io_wire_retry_attempts = io_wire_retry_attempts;
        rawstor_opts_initialize(&opts);
    }
    WireRetryOptsOverride(const WireRetryOptsOverride&) = delete;
    WireRetryOptsOverride(WireRetryOptsOverride&&) = delete;

    ~WireRetryOptsOverride() { rawstor_opts_initialize(nullptr); }

    WireRetryOptsOverride& operator=(const WireRetryOptsOverride&) = delete;
    WireRetryOptsOverride& operator=(WireRetryOptsOverride&&) = delete;
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
            Result result;
            int res = rawstor_object_close(_object, result_cb, &result);
            if (res < 0) {
                rawstd_error("%s\n", strerror(-res));
            } else {
                try {
                    while (!result.done) {
                        _queue.wait();
                    }
                } catch (const std::exception& e) {
                    rawstd_error("%s\n", e.what());
                }
                if (result.error) {
                    rawstd_error("%s\n", strerror(result.error));
                }
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
        ssize_t res =
            rawstor::tests::sync_run(_queue, [&](auto cb, void* data) {
                return rawstor_target_create(
                    _queue, target.c_str(), &spec, cb, data
                );
            });
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR((int)-res);
        }

        try {
            ssize_t ores =
                rawstor::tests::sync_run(_queue, [&](auto cb, void* data) {
                    return rawstor_target_open(
                        _queue, _target.c_str(), &_object, cb, data
                    );
                });
            if (ores < 0) {
                RAWSTD_THROW_SYSTEM_ERROR((int)-ores);
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
        try {
            rawstor::tests::sync_run(_queue, [&](auto cb, void* data) {
                return rawstor_target_remove(_queue, _target.c_str(), cb, data);
            });
        } catch (const std::exception& e) {
            rawstd_error("%s\n", e.what());
        }
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
        ssize_t res =
            rawstor::tests::sync_run(_queue, [&](auto cb, void* data) {
                return rawstor_object_flush(_object, cb, data);
            });
        if (res < 0) {
            RAWSTD_THROW_SYSTEM_ERROR((int)-res);
        }
    }

    void discard(size_t size) {
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
        int res = rawstor_object_discard(_object, size, 0, callback, cb.get());
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

    void write_zeroes(size_t size, bool unmap, bool sync) {
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
        int res = rawstor_object_write_zeroes(
            _object, size, 0, unmap, sync, callback, cb.get()
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(RAWSTOR_MAGIC, 1, 4);
        s.cmd_read(RAWSTOR_MAGIC, 2, "pong", 4);
        // Object's destructor closes -- close() now flushes first (see
        // Object::close()'s own doc comment) since the write above left it
        // dirty.
        s.cmd_flush(RAWSTOR_MAGIC, 3, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));

    std::string pong(4, '\0');
    EXPECT_NO_THROW(object.read(pong.data(), pong.length()));
    EXPECT_EQ(pong, "pong");
}

TEST(OstIOTest, discard_and_write_zeroes) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_discard(RAWSTOR_MAGIC, 1, 4);
        s.cmd_write_zeroes(RAWSTOR_MAGIC, 2, 4);
        // Object's destructor closes -- close() now flushes first (see
        // Object::close()'s own doc comment); write_zeroes() left it dirty
        // the same way pwrite() does.
        s.cmd_flush(RAWSTOR_MAGIC, 3, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    EXPECT_NO_THROW(object.discard(4));
    EXPECT_NO_THROW(object.write_zeroes(4, /*unmap=*/false, /*sync=*/false));
}

TEST(OstIOTest, flush) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // Connection::open()'s own first attempt (against the session
    // create() already connected) plus invalidate_session()'s own
    // internal retry (rawstor_opts_io_attempts() attempts) -- one more
    // than io_attempts total.
    for (unsigned int i = 0; i < 4; ++i) {
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // See set_object_fail above for why this is one more than
    // rawstor_opts_io_attempts().
    for (unsigned int i = 0; i < 4; ++i) {
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // See set_object_fail above for why this is one more than
    // rawstor_opts_io_attempts().
    for (unsigned int i = 0; i < 4; ++i) {
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write(0, 1, 4);
    }

    {
        rawstor::tests::Session s(server);
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // ENOENT is a permanent backend rejection (see Connection::_with_retry()'s
    // is_permanent_backend_error()): the connection is fine, so this
    // never reconnects, and retrying can never turn ENOENT into success,
    // so it doesn't retry at all -- exactly one session handles both
    // SET_OBJECT and the WRITE.
    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, -ENOENT);
    }

    {
        rawstor::tests::Session s(server);
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
        // Object's destructor closes -- close() now flushes first since
        // the write above left it dirty.
        s.cmd_flush(RAWSTOR_MAGIC, 3, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));
}

// Same shape as write_busy_retries_without_reconnect above, but with a
// generic (non-EBUSY) backend rejection -- ENOSPC here, retryable since
// it's not in Connection::_with_retry()'s is_permanent_backend_error()
// list. Confirms that same-session, no-reconnect retry is BackendError's
// general behavior now, not something special-cased to EBUSY alone.
TEST(OstIOTest, write_backend_error_retries_without_reconnect) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, -ENOSPC);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 2, 4);
        s.cmd_flush(RAWSTOR_MAGIC, 3, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));
}

// A hash mismatch is a well-formed response (EBADMSG in body.res, see
// ost/src/client.cpp), but unlike the EBUSY/ENOSPC cases above it must
// NOT retry on the same session: it means the client and server disagree
// about the payload just sent, so neither side can trust it still knows
// where the next frame header begins. The first session only ever sees
// ONE WRITE -- if the retry reused it instead of reconnecting, this
// session would see a second WRITE next and the real (never-scripted)
// one would hang waiting for a connection nothing accepts.
TEST(OstIOTest, write_hash_mismatch_reconnects) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, -EBADMSG);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, 4);
        s.cmd_flush(RAWSTOR_MAGIC, 2, 0);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Object object(queue, target, 1ull << 20);

    std::string ping = "ping";
    EXPECT_NO_THROW(object.write(ping.data(), ping.length()));
}

// Proves io_attempts and io_wire_retry_attempts are independent budgets:
// io_attempts is set well below the number of wire failures scripted
// here, so a TransportError retry that were (still) bounded by it would
// fail well before the write below actually succeeds.
TEST(OstIOTest, write_wire_retries_exceed_io_attempts) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    WireRetryOptsOverride opts_guard(
        /*io_attempts=*/1, /*io_wire_retry_attempts=*/3
    );

    // The first two sessions each die right after accepting the WRITE
    // request (no response), forcing a reconnect (and thus a fresh
    // SET_OBJECT) each time before the third finally answers.
    for (unsigned int i = 0; i < 2; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
    }

    {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
        s.cmd_write_response(RAWSTOR_MAGIC, 1, 4);
        s.cmd_flush(RAWSTOR_MAGIC, 2, 0);
    }

    {
        rawstor::tests::Session s(server);
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
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    for (unsigned int i = 0; i < 3; ++i) {
        rawstor::tests::Session s(server);
        s.cmd_set_object(RAWSTOR_MAGIC, 0, 0);
        s.cmd_write_request(4);
    }

    {
        rawstor::tests::Session s(server);
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

// Answers whatever WRITE frames actually arrive next on `server` (echoing
// each one's own cid, since a retried write's cid isn't something a test
// can predict up front). This reacts to each frame's own header instead
// of pre-committing to a fixed count of reads: a fixed script of N
// pre-queued Server::read() calls leaves their N-1'th response enqueued
// only from inside the (N-1)'th read's own callback, which lands *behind*
// whichever of the other N-1 pre-queued reads are still sitting
// unconsumed in front of it -- and Server::read() has no timeout, so a
// read nothing ever satisfies (because fewer than N writes actually
// showed up) blocks the fake server's command thread forever, along with
// everything scripted after it.
//
// Every write left dirty (rawstor_object_pwrite() is called with
// sync=false below) makes Object::close() issue one real FLUSH over this
// same connection before closing it -- answered here once it arrives.
// Object::close() itself never sends a wire-level RELEASE (Session::close()
// is a local socket close, not a protocol op); that only happens
// afterwards, when ~Object() calls rawstor_target_remove(), which opens
// its own brand new single-session Connection to send it -- so once the
// object's connection is closed from this side too (mirroring the real
// client, which does the same right after flush() returns), this scripts
// a fresh accept() and answers that RELEASE on the new connection.
void auto_respond_writes_then_flush_and_release(
    rawstor::tests::Server& server, size_t write_payload_size,
    int32_t write_res, int32_t flush_res, int32_t release_res
) {
    server.read(
        "OST frame head <<<", sizeof(RawstorOSTFrameHead),
        [&server, write_payload_size, write_res, flush_res,
         release_res](const void* buf) {
            RawstorOSTFrameHead head =
                *static_cast<const RawstorOSTFrameHead*>(buf);
            if (head.cmd == RAWSTOR_CMD_WRITE) {
                size_t rest_size = sizeof(RawstorOSTFrameIO) -
                                   sizeof(RawstorOSTFrameHead) +
                                   write_payload_size;
                server.read(
                    "RAWSTOR_CMD_WRITE (rest) <<<", rest_size,
                    [&server, head, write_res, write_payload_size, flush_res,
                     release_res](const void*) {
                        RawstorOSTFrameResponse response = {
                            .head{
                                .magic = RAWSTOR_MAGIC,
                                .cmd = RAWSTOR_CMD_WRITE,
                                .cid = head.cid,
                            },
                            .body = {.res = write_res, .hash = 0},
                        };
                        server.write(
                            "RAWSTOR_CMD_WRITE >>>", &response, sizeof(response)
                        );
                        auto_respond_writes_then_flush_and_release(
                            server, write_payload_size, write_res, flush_res,
                            release_res
                        );
                    }
                );
            } else if (head.cmd == RAWSTOR_CMD_FLUSH) {
                size_t rest_size =
                    sizeof(RawstorOSTFrameBasic) - sizeof(RawstorOSTFrameHead);
                server.read(
                    "RAWSTOR_CMD_FLUSH (rest) <<<", rest_size,
                    [&server, head, flush_res, release_res](const void*) {
                        RawstorOSTFrameResponse response = {
                            .head{
                                .magic = RAWSTOR_MAGIC,
                                .cmd = RAWSTOR_CMD_FLUSH,
                                .cid = head.cid,
                            },
                            .body = {.res = flush_res, .hash = 0},
                        };
                        server.write(
                            "RAWSTOR_CMD_FLUSH >>>", &response, sizeof(response)
                        );
                        server.close("SESSION >>> (after flush)");
                        server.accept("SESSION <<< (target remove)");
                        server.read(
                            "RAWSTOR_CMD_RELEASE <<<",
                            sizeof(RawstorOSTFrameBasic), [](const void*) {}
                        );
                        RawstorOSTFrameResponse release_response = {
                            .head{
                                .magic = RAWSTOR_MAGIC,
                                .cmd = RAWSTOR_CMD_RELEASE,
                                .cid = 0,
                            },
                            .body = {.res = release_res, .hash = 0},
                        };
                        server.write(
                            "RAWSTOR_CMD_RELEASE >>>", &release_response,
                            sizeof(release_response)
                        );
                    }
                );
            } else {
                throw std::runtime_error(
                    "auto_respond_writes_then_flush_and_release: unexpected "
                    "command magic=" +
                    std::to_string(head.magic) +
                    " cmd=" + std::to_string(head.cmd) +
                    " cid=" + std::to_string(head.cid)
                );
            }
        }
    );
}

// Regression: two writes share one session. The first gets a well-formed
// response carrying an unexpected cmd (a TransportError -- see
// session_error.hpp -- not a dropped connection: nothing about the wire
// ever looks broken, no FIN/RST at any point), which
// Connection::_with_retry() reacts to by calling invalidate_session():
// swap in a fresh session, then Session::close() the old one. The second
// write is already sitting in that same old session's _ops, purely
// waiting on a response of its own, when this happens -- _recv_pump has
// nothing of its own to ever notice here (the connection was never
// actually broken), so it can't be what rescues it. Session::close()
// must fail whatever is still in _ops itself, or the second write has
// nothing left watching it and hangs forever.
//
// This is deliberately built around a same-session *framing* error
// rather than a dropped connection: on a real loopback socket, closing
// the connection also sends the second write's own recv_pump a FIN it
// can (and, empirically, reliably does) notice on its own first, via the
// *pre-existing* correct handling of a genuine transport error --
// resolving the second write correctly regardless of the fix under test
// and making that version of this scenario nondeterministic. Answering
// with a well-formed-but-wrong-cmd response instead means nothing on the
// wire ever looks wrong at the socket level, so there's nothing for
// recv_pump to independently detect; the only thing that can ever tear
// this session down is the explicit invalidate_session() -> Session::
// close() path this test exists to cover. (A genuine backend rejection,
// e.g. res = -EIO, no longer reconnects at all since the wire/backend
// split -- see Connection::_with_retry() -- so it can't drive this
// scenario anymore; only a wire-classified failure like this one still
// does.)
TEST(OstIOTest, write_orphaned_by_sibling_error_response) {
    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // Scripted with the raw Server API instead of Session: Session's
    // destructor unconditionally queues an actual close() of the
    // connection, which would send a FIN -- exactly what this test needs
    // to avoid (see the TEST's own doc comment above). This session is
    // instead left to the client's own invalidate_session() to tear
    // down; the server side only ever forget()s its bookkeeping of it
    // (see forget()'s own doc comment in server.hpp).
    server.accept("SESSION <<<");
    server.read(
        "RAWSTOR_CMD_SET_OBJECT <<<", sizeof(RawstorOSTFrameBasic),
        [](const void*) {}
    );
    RawstorOSTFrameResponse set_object_response = {
        .head{
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = 0,
        },
        .body = {.res = 0, .hash = 0},
    };
    server.write(
        "RAWSTOR_CMD_SET_OBJECT >>>", &set_object_response,
        sizeof(set_object_response)
    );
    server.read(
        "RAWSTOR_CMD_WRITE <<<", sizeof(RawstorOSTFrameIO) + 4,
        [&server](const void* buf) {
            uint16_t cid = static_cast<const RawstorOSTFrameIO*>(buf)->head.cid;
            // A well-formed response with the wrong cmd -- validate_cmd()
            // rejects it as EPROTO, a TransportError, not a real backend
            // rejection (see this TEST's own doc comment for why that
            // distinction matters here).
            RawstorOSTFrameResponse wrong_cmd_response = {
                .head{
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_FLUSH,
                    .cid = cid,
                },
                .body = {.res = 0, .hash = 0},
            };
            server.write(
                "RAWSTOR_CMD_WRITE >>> (wrong cmd)", &wrong_cmd_response,
                sizeof(wrong_cmd_response)
            );

            // Only scripted now, from inside this callback, instead of
            // up front alongside the session above: queued upfront,
            // this would already be sitting in the fake server's command
            // queue *before* the write-request read callback here ever
            // runs, so the server would work through this retry
            // session's accept()/etc. commands first and never actually
            // reach the error response above at all. Scripted here,
            // after that response is already queued to go out, it's
            // guaranteed to sit behind it.
            server.forget("SESSION (forgotten, connection left for the OS)");
            server.accept("SESSION <<< (retry target)");
            server.read(
                "RAWSTOR_CMD_SET_OBJECT <<<", sizeof(RawstorOSTFrameBasic),
                [](const void*) {}
            );
            RawstorOSTFrameResponse retry_set_object_response = {
                .head{
                    .magic = RAWSTOR_MAGIC,
                    .cmd = RAWSTOR_CMD_SET_OBJECT,
                    .cid = 0,
                },
                .body = {.res = 0, .hash = 0},
            };
            server.write(
                "RAWSTOR_CMD_SET_OBJECT >>>", &retry_set_object_response,
                sizeof(retry_set_object_response)
            );
            // Answers every WRITE that actually arrives (the retried
            // first write and the second write, in whatever order they
            // land) with its own cid echoed back, then the one FLUSH and
            // RELEASE the Object destructor and rawstor_target_remove()
            // send at the very end of this test, the latter on its own
            // fresh connection.
            auto_respond_writes_then_flush_and_release(server, 4, 4, 0, 0);
        }
    );

    Object object(queue, target, 1ull << 20);

    bool done1 = false;
    int err1 = 0;
    auto cb1 = std::make_unique<std::function<void(size_t, int)>>(
        [&done1, &err1](size_t, int error) {
            done1 = true;
            err1 = error;
        }
    );
    bool done2 = false;
    int err2 = 0;
    auto cb2 = std::make_unique<std::function<void(size_t, int)>>(
        [&done2, &err2](size_t, int error) {
            done2 = true;
            err2 = error;
        }
    );

    std::string ping = "ping";
    std::string pong = "pong";

    // Issued back to back, with no rawio_wait_timeout() in between:
    // Session::_add_op() registers both into _ops before either's own
    // send is even submitted (io_uring only actually submits inside
    // Queue::wait()), so the second write is guaranteed to already be
    // sitting in _ops, on the one session both share, well before the
    // first write's own round trip -- send, the server's error response,
    // Connection::_with_retry() reacting to it -- can possibly run.
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

    // Bounded pump, same reasoning as write_disconnect_concurrent above:
    // an orphaned write would otherwise hang this loop -- and the whole
    // test binary -- forever.
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
    EXPECT_EQ(err1, 0);
    EXPECT_EQ(err2, 0);
}

// Regression: many writes share one session, all lose it at once (a
// genuine close, matching a real dropped connection). Session::
// _fail_in_flight() force-fails every one of them synchronously, in a
// single loop, so their Connection::_with_retry() coroutines all resume
// in a tight burst -- each one's own invalidate_session(s) call races
// the very same `s`: exactly one wins Connection::_reconnecting's dedup
// and actually reconnects, the rest return immediately and fall straight
// into their own backoff wait (Queue::timeout()), submitted back to back
// against the same io_uring ring before any of them has had a chance to
// pump a completion. This is the exact concurrency shape a real host
// under load produces (many in-flight guest writes, one dropped OST
// connection) -- and the shape this test exists to stress, since nothing
// above exercises more than two concurrent ops at once.
//
// Genuinely requires RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE to be nonzero,
// not just to "mean more" -- at the harness default (0, see tests/
// main.cpp's own doc comment for why) every deduped op's retry is
// immediate, so most of them race back to get_next_session() before the
// winning reconnect above has actually installed the replacement,
// collide with the still-stale session again, and burn through
// io_wire_retry_attempts on a single scripted reconnect this test never
// meant to need more than once. Skipped rather than run meaninglessly
// (or flakily) at 0 -- run with e.g.
// `RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE=20` to actually exercise it.
TEST(OstIOTest, write_many_concurrent_wire_errors_with_backoff) {
    if (rawstor_opts_io_retry_backoff_base() == 0) {
        GTEST_SKIP() << "needs a nonzero RAWSTOR_OPTS_IO_RETRY_BACKOFF_BASE "
                        "-- see this TEST's own doc comment";
    }

    constexpr int kWrites = 15;

    Queue queue(16);
    rawstor::tests::Server server(8753, 256);
    std::string target =
        "ost://127.0.0.1:8753/00000000-0000-7000-8000-000000000000";

    {
        rawstor::tests::Session s(server);
        s.cmd_allocate(RAWSTOR_MAGIC, 0, 0);
    }

    // Raw Server API, same reasoning as write_orphaned_by_sibling_error_
    // response above: this session's own close() is scripted explicitly,
    // from inside the last write's own read callback, instead of via
    // Session's destructor (which would queue it too early, before any
    // of these kWrites requests has actually arrived).
    server.accept("SESSION <<<");
    server.read(
        "RAWSTOR_CMD_SET_OBJECT <<<", sizeof(RawstorOSTFrameBasic),
        [](const void*) {}
    );
    RawstorOSTFrameResponse set_object_response = {
        .head{
            .magic = RAWSTOR_MAGIC,
            .cmd = RAWSTOR_CMD_SET_OBJECT,
            .cid = 0,
        },
        .body = {.res = 0, .hash = 0},
    };
    server.write(
        "RAWSTOR_CMD_SET_OBJECT >>>", &set_object_response,
        sizeof(set_object_response)
    );
    // Reads every one of the kWrites requests -- none of them ever gets
    // a response -- then closes on the last one, guaranteeing all
    // kWrites were fully sent (and are sitting in _ops) before the
    // connection dies out from under all of them at once.
    auto remaining = std::make_shared<int>(kWrites);
    for (int i = 0; i < kWrites; ++i) {
        server.read(
            "RAWSTOR_CMD_WRITE <<<", sizeof(RawstorOSTFrameIO) + 4,
            [&server, remaining](const void*) {
                if (--*remaining == 0) {
                    server.close("SESSION >>> (after all writes, unanswered)");

                    server.accept("SESSION <<< (retry target)");
                    server.read(
                        "RAWSTOR_CMD_SET_OBJECT <<<",
                        sizeof(RawstorOSTFrameBasic), [](const void*) {}
                    );
                    RawstorOSTFrameResponse retry_set_object_response = {
                        .head{
                            .magic = RAWSTOR_MAGIC,
                            .cmd = RAWSTOR_CMD_SET_OBJECT,
                            .cid = 0,
                        },
                        .body = {.res = 0, .hash = 0},
                    };
                    server.write(
                        "RAWSTOR_CMD_SET_OBJECT >>>",
                        &retry_set_object_response,
                        sizeof(retry_set_object_response)
                    );
                    // Answers every retried WRITE (in whatever order they
                    // land) with its own cid echoed back, then the one
                    // FLUSH and RELEASE the Object destructor and
                    // rawstor_target_remove() send at the very end of
                    // this test, the latter on its own fresh connection.
                    auto_respond_writes_then_flush_and_release(
                        server, 4, 4, 0, 0
                    );
                }
            }
        );
    }

    Object object(queue, target, 1ull << 20);

    bool done[kWrites] = {};
    int err[kWrites] = {};
    std::string payload = "ping";

    // Issued back to back, with no rawio_wait_timeout() in between --
    // same reasoning as write_orphaned_by_sibling_error_response above,
    // just kWrites-wide instead of two: every one of them is sitting in
    // _ops, on the one session they all share, before any of their sends
    // -- let alone the connection dying -- has had a chance to run.
    for (int i = 0; i < kWrites; ++i) {
        auto cb = std::make_unique<std::function<void(size_t, int)>>(
            [&done, &err, i](size_t, int error) {
                done[i] = true;
                err[i] = error;
            }
        );
        int res = rawstor_object_pwrite(
            object.raw(), payload.data(), payload.length(), i * 4, false,
            callback, cb.get()
        );
        ASSERT_GE(res, 0);
        cb.release();
    }

    // Bounded pump, same reasoning as every other test above: an
    // orphaned write -- or a lost Queue::timeout() completion stranding
    // a backoff wait forever -- would otherwise hang this loop, and the
    // whole test binary, forever.
    unsigned int budget_ms = rawstor_opts_tcp_user_timeout() + 5000;
    auto all_done = [&done] {
        for (bool d : done) {
            if (!d) {
                return false;
            }
        }
        return true;
    };
    for (unsigned int elapsed_ms = 0; elapsed_ms < budget_ms && !all_done();
         elapsed_ms += 100) {
        int wres = rawio_wait_timeout(queue, 100);
        if (wres < 0 && wres != -ETIME) {
            break;
        }
    }

    for (int i = 0; i < kWrites; ++i) {
        EXPECT_TRUE(done[i]) << "write " << i << " orphaned (never completed)";
        EXPECT_EQ(err[i], 0) << "write " << i;
    }
}

} // unnamed namespace
