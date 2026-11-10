#include "object.hpp"

#include <rawio/awaitable.hpp>
#include <rawio/queue.hpp>

#include <rawstd/coro.hpp>

#include <rawstor/object.h>
#include <rawstor/rawio.h>

#include <gtest/gtest.h>

#include <cerrno>
#include <memory>
#include <stdexcept>

/*
 * An exception that is not a std::system_error still reaches the callback
 * of an I/O call as an error: the caller of the C API has nothing else to
 * learn that its request is over, and waits for it forever otherwise.
 */

namespace {

class FailingObject final : public rawstor::Object {
private:
    bool _suspend;
    bool* _destroyed;

    rawstd::Task<size_t> _fail_size() {
        if (_suspend) {
            co_await _queue.timeout(1000);
        }
        throw std::runtime_error("unexpected failure");
    }

    rawstd::Task<void> _fail_void() {
        if (_suspend) {
            co_await _queue.timeout(1000);
        }
        throw std::runtime_error("unexpected failure");
    }

    rawstd::Task<bool> _fail_bool() {
        if (_suspend) {
            co_await _queue.timeout(1000);
        }
        throw std::runtime_error("unexpected failure");
    }

public:
    FailingObject(rawio::Queue& queue, bool suspend, bool* destroyed) :
        rawstor::Object(queue, RawstdUUID{}, RawstdUUID{}, 4096),
        _suspend(suspend),
        _destroyed(destroyed) {}

    ~FailingObject() override { *_destroyed = true; }

    rawstd::Task<size_t> pread(void*, size_t, uint64_t) override {
        return _fail_size();
    }

    rawstd::Task<size_t>
    preadv(iovec*, unsigned int, size_t, uint64_t) override {
        return _fail_size();
    }

    rawstd::Task<size_t> pwrite(const void*, size_t, uint64_t, bool) override {
        return _fail_size();
    }

    rawstd::Task<size_t>
    pwritev(const iovec*, unsigned int, size_t, uint64_t, bool) override {
        return _fail_size();
    }

    rawstd::Task<size_t> discard(size_t, uint64_t) override {
        return _fail_size();
    }

    rawstd::Task<size_t> write_zeroes(size_t, uint64_t, bool, bool) override {
        return _fail_size();
    }

    rawstd::Task<void> flush() override { return _fail_void(); }

    rawstd::Task<void> user_data(uint64_t, uint8_t*, uint64_t*) override {
        return _fail_void();
    }

    rawstd::Task<bool> user_data_cas(
        uint64_t, const uint8_t*, const uint8_t*, uint8_t*, uint64_t*
    ) override {
        return _fail_bool();
    }

    rawstd::Task<void> close(bool) override { return _fail_void(); }
};

struct IoResult {
    bool done = false;
    size_t result = 0;
    int error = 0;
};

struct Result {
    bool done = false;
    ssize_t result = 0;
};

int io_callback(size_t result, int error, void* data) {
    IoResult* r = static_cast<IoResult*>(data);
    r->done = true;
    r->result = result;
    r->error = error;
    return 0;
}

int callback(ssize_t result, void* data) {
    Result* r = static_cast<Result*>(data);
    r->done = true;
    r->result = result;
    return 0;
}

class ObjectErrorsTest : public testing::TestWithParam<bool> {
protected:
    std::unique_ptr<rawio::Queue> queue = rawio::Queue::create(2);
    bool destroyed = false;
    std::unique_ptr<FailingObject> object =
        std::make_unique<FailingObject>(*queue, GetParam(), &destroyed);

    template <typename R>
    void wait(const R& r) {
        while (!r.done) {
            ASSERT_GE(rawio_wait(queue.get()), 0);
        }
    }
};

} // namespace

TEST_P(ObjectErrorsTest, pwrite_reports_unexpected_exception) {
    char buf[16] = {};
    IoResult r;
    ASSERT_EQ(
        rawstor_object_pwrite(
            object.get(), buf, sizeof(buf), 0, false, io_callback, &r
        ),
        0
    );
    wait(r);
    EXPECT_EQ(r.error, EINVAL);
    EXPECT_EQ(r.result, 0u);
}

TEST_P(ObjectErrorsTest, pread_reports_unexpected_exception) {
    char buf[16];
    IoResult r;
    ASSERT_EQ(
        rawstor_object_pread(
            object.get(), buf, sizeof(buf), 0, io_callback, &r
        ),
        0
    );
    wait(r);
    EXPECT_EQ(r.error, EINVAL);
}

TEST_P(ObjectErrorsTest, flush_reports_unexpected_exception) {
    Result r;
    ASSERT_EQ(rawstor_object_flush(object.get(), callback, &r), 0);
    wait(r);
    EXPECT_EQ(r.result, -EINVAL);
}

TEST_P(ObjectErrorsTest, user_data_reports_unexpected_exception) {
    uint8_t value[RAWSTOR_OBJECT_USER_DATA_SIZE];
    Result r;
    ASSERT_EQ(
        rawstor_object_user_data(object.get(), 0, value, nullptr, callback, &r),
        0
    );
    wait(r);
    EXPECT_EQ(r.result, -EINVAL);
}

TEST_P(ObjectErrorsTest, user_data_cas_reports_unexpected_exception) {
    uint8_t expected[RAWSTOR_OBJECT_USER_DATA_SIZE] = {};
    uint8_t desired[RAWSTOR_OBJECT_USER_DATA_SIZE] = {1};
    uint8_t current[RAWSTOR_OBJECT_USER_DATA_SIZE];
    Result r;
    ASSERT_EQ(
        rawstor_object_user_data_cas(
            object.get(), 0, expected, desired, current, nullptr, callback, &r
        ),
        0
    );
    wait(r);
    EXPECT_EQ(r.result, -EINVAL);
}

TEST_P(ObjectErrorsTest, close_reports_unexpected_exception_and_deletes) {
    Result r;
    RawstorObject* raw = object.release();
    ASSERT_EQ(rawstor_object_close(raw, callback, &r), 0);
    wait(r);
    EXPECT_EQ(r.result, -EINVAL);
    EXPECT_TRUE(destroyed);
}

INSTANTIATE_TEST_SUITE_P(
    Suspension, ObjectErrorsTest, testing::Bool(),
    [](const testing::TestParamInfo<bool>& info) {
        return info.param ? "after_suspension" : "immediately";
    }
);
