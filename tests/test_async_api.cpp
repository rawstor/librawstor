#include "server.hpp"
#include "session.hpp"

#include <rawstd/gpp.hpp>

#include <rawstor/object.h>
#include <rawstor/protocol.h>
#include <rawstor/rawio.h>

#include <gtest/gtest.h>

#include <filesystem>
#include <fstream>
#include <sstream>
#include <string>

#include <cerrno>

namespace {

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

struct AsyncResult {
    int result = 1;
    int calls = 0;
};

int async_cb(int result, void* data) {
    AsyncResult* r = static_cast<AsyncResult*>(data);
    r->result = result;
    ++r->calls;
    return 0;
}

struct AsyncOpenResult {
    RawstorObject* object = nullptr;
    int result = 1;
    int calls = 0;
};

int async_open_cb(RawstorObject* object, int result, void* data) {
    AsyncOpenResult* r = static_cast<AsyncOpenResult*>(data);
    r->object = object;
    r->result = result;
    ++r->calls;
    return 0;
}

void wait_calls(Queue& q, const int& calls) {
    while (calls == 0) {
        q.wait();
    }
}

std::string file_target(const char* dir, const char* uuid) {
    std::filesystem::path path =
        std::filesystem::temp_directory_path() / dir / uuid;
    std::ostringstream oss;
    oss << "file://" << path.string();
    return oss.str();
}

TEST(FileAsyncLifecycleTest, create_spec_open_remove) {
    std::string target = file_target(
        "test_objects_async", "00000000-0000-7000-8000-000000000001"
    );

    Queue q(64);

    {
        RawstorObjectSpec spec{};
        spec.size = 1ull << 20;
        AsyncResult r;
        ASSERT_EQ(
            rawstor_object_create_async(q, target.c_str(), &spec, async_cb, &r),
            0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.calls, 1);
        EXPECT_EQ(r.result, 0);
    }

    {
        RawstorObjectSpec read_spec{};
        AsyncResult r;
        ASSERT_EQ(
            rawstor_object_spec_async(
                q, target.c_str(), &read_spec, async_cb, &r
            ),
            0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.calls, 1);
        EXPECT_EQ(r.result, 0);
        EXPECT_EQ(read_spec.size, 1ull << 20);
    }

    {
        AsyncOpenResult r;
        ASSERT_EQ(
            rawstor_object_open_async(q, target.c_str(), async_open_cb, &r), 0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.calls, 1);
        EXPECT_EQ(r.result, 0);
        ASSERT_NE(r.object, nullptr);
        EXPECT_EQ(rawstor_object_close(r.object), 0);
    }

    {
        AsyncResult r;
        ASSERT_EQ(
            rawstor_object_remove_async(q, target.c_str(), async_cb, &r), 0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.calls, 1);
        EXPECT_EQ(r.result, 0);
    }

    {
        RawstorObjectSpec read_spec{};
        AsyncResult r;
        ASSERT_EQ(
            rawstor_object_spec_async(
                q, target.c_str(), &read_spec, async_cb, &r
            ),
            0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.result, -ENOENT);
    }
}

TEST(FileAsyncLifecycleTest, open_missing_object) {
    std::string target = file_target(
        "test_objects_async", "00000000-0000-7000-8000-0000000000ff"
    );

    Queue q(64);

    AsyncOpenResult r;
    ASSERT_EQ(
        rawstor_object_open_async(q, target.c_str(), async_open_cb, &r), 0
    );
    wait_calls(q, r.calls);
    EXPECT_EQ(r.calls, 1);
    EXPECT_LT(r.result, 0);
    EXPECT_EQ(r.object, nullptr);
}

TEST(FileAsyncLifecycleTest, invalid_target_reports_immediately) {
    Queue q(64);

    /* The target filename is not a valid UUID. */
    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    AsyncResult r;
    EXPECT_LT(
        rawstor_object_create_async(
            q, "file:///tmp/not-a-uuid", &spec, async_cb, &r
        ),
        0
    );
    EXPECT_EQ(r.calls, 0);
}

TEST(FileAsyncCreateTest, rollback_on_partial_failure) {
    namespace fs = std::filesystem;

    const char* uuid = "00000000-0000-7000-8000-00000000abcd";
    fs::path base = fs::temp_directory_path() / "test_rollback_async";
    fs::remove_all(base);
    fs::create_directories(base);

    /*
     * The second target cannot be created: its backing directory path goes
     * through a regular file, so mkdir() fails with ENOTDIR. The first
     * target must be rolled back.
     */
    fs::path good = base / "good";
    fs::path blocker = base / "blocker";
    std::ofstream(blocker.string()) << "not a directory";

    std::ostringstream oss;
    oss << "file://" << good.string() << "/" << uuid << ",file://"
        << (blocker / "sub").string() << "/" << uuid;
    std::string target = oss.str();

    Queue q(64);

    RawstorObjectSpec spec{};
    spec.size = 1ull << 20;
    AsyncResult r;
    ASSERT_EQ(
        rawstor_object_create_async(q, target.c_str(), &spec, async_cb, &r), 0
    );
    wait_calls(q, r.calls);
    EXPECT_EQ(r.calls, 1);
    EXPECT_LT(r.result, 0);

    std::ostringstream dat;
    dat << uuid << ".dat";
    std::ostringstream spec_file;
    spec_file << uuid << ".spec";
    EXPECT_FALSE(fs::exists(good / dat.str()));
    EXPECT_FALSE(fs::exists(good / spec_file.str()));

    fs::remove_all(base);
}

TEST(OstAsyncLifecycleTest, create_remove) {
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
        s.cmd_handshake();
        s.cmd_release(RAWSTOR_MAGIC, 0, 0);
    }

    Queue q(256);

    {
        RawstorObjectSpec spec{};
        spec.size = 1ull << 20;
        AsyncResult r;
        ASSERT_EQ(
            rawstor_object_create_async(q, target.c_str(), &spec, async_cb, &r),
            0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.calls, 1);
        EXPECT_EQ(r.result, 0);
    }

    {
        AsyncResult r;
        ASSERT_EQ(
            rawstor_object_remove_async(q, target.c_str(), async_cb, &r), 0
        );
        wait_calls(q, r.calls);
        EXPECT_EQ(r.calls, 1);
        EXPECT_EQ(r.result, 0);
    }
}

} // unnamed namespace
