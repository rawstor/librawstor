#include "worker.hpp"

#include <rawio/queue.hpp>

#include <gtest/gtest.h>

#include <functional>
#include <system_error>
#include <thread>

#include <cerrno>

namespace {

int run_work(rawio::Queue& q, std::function<int()>&& work) {
    bool done = false;
    int result = -1;

    rawstor::run_in_worker(q, std::move(work), [&done, &result](int error) {
        result = error;
        done = true;
    });

    while (!done) {
        q.wait_timeout(1000);
    }

    return result;
}

TEST(WorkerTest, success) {
    std::unique_ptr<rawio::Queue> q = rawio::Queue::create(64);

    EXPECT_EQ(run_work(*q, []() { return 0; }), 0);
}

TEST(WorkerTest, error) {
    std::unique_ptr<rawio::Queue> q = rawio::Queue::create(64);

    EXPECT_EQ(run_work(*q, []() { return EACCES; }), EACCES);
}

TEST(WorkerTest, thrown_system_error) {
    std::unique_ptr<rawio::Queue> q = rawio::Queue::create(64);

    EXPECT_EQ(
        run_work(
            *q,
            []() -> int {
                throw std::system_error(ENOSPC, std::generic_category());
            }
        ),
        ENOSPC
    );
}

TEST(WorkerTest, thrown_exception) {
    std::unique_ptr<rawio::Queue> q = rawio::Queue::create(64);

    EXPECT_EQ(
        run_work(*q, []() -> int { throw std::runtime_error("boom"); }), EIO
    );
}

TEST(WorkerTest, runs_off_the_calling_thread) {
    std::unique_ptr<rawio::Queue> q = rawio::Queue::create(64);

    std::thread::id worker_id;
    EXPECT_EQ(
        run_work(
            *q,
            [&worker_id]() {
                worker_id = std::this_thread::get_id();
                return 0;
            }
        ),
        0
    );

    EXPECT_NE(worker_id, std::this_thread::get_id());
}

TEST(WorkerTest, many_concurrent) {
    std::unique_ptr<rawio::Queue> q = rawio::Queue::create(256);

    const int n = 32;
    int completed = 0;
    int failures = 0;

    for (int i = 0; i < n; ++i) {
        int expected = (i % 3 == 0) ? EIO : 0;
        rawstor::run_in_worker(
            *q, [expected]() { return expected; },
            [&completed, &failures, expected](int error) {
                if (error != expected) {
                    ++failures;
                }
                ++completed;
            }
        );
    }

    while (completed < n) {
        q->wait_timeout(1000);
    }

    EXPECT_EQ(failures, 0);
}

} // unnamed namespace
