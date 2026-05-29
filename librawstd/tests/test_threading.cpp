#include "rawstd/threading.h"

#include <gtest/gtest.h>

#include <time.h>
#include <unistd.h>

#include <vector>

#include <cassert>
#include <cstddef>
#include <cstdlib>

namespace {

struct TestThreadingContext {
    RawstdMutex* mutex;
    RawstdCond* cond;

    int wait;
    int value;
};

void* test_thread(void* data) {
    TestThreadingContext* context = static_cast<TestThreadingContext*>(data);

    rawstd_mutex_lock(context->mutex);
    ++context->wait;
    rawstd_cond_wait(context->cond, context->mutex);
    --context->wait;
    ++context->value;
    rawstd_mutex_unlock(context->mutex);

    return context;
}

TEST(CondTest, signal) {
    TestThreadingContext context = (TestThreadingContext){
        .mutex = rawstd_mutex_create(),
        .cond = rawstd_cond_create(),
        .wait = 0,
        .value = 0,
    };

    EXPECT_NE(context.mutex, nullptr);
    EXPECT_NE(context.cond, nullptr);

    RawstdThread* thread = rawstd_thread_create(test_thread, &context);

    while (1) {
        rawstd_mutex_lock(context.mutex);
        if (context.wait == 1) {
            rawstd_mutex_unlock(context.mutex);
            break;
        }
        rawstd_mutex_unlock(context.mutex);
        usleep(1000);
    }

    rawstd_mutex_lock(context.mutex);
    rawstd_cond_signal(context.cond);
    rawstd_mutex_unlock(context.mutex);

    void* data = rawstd_thread_join(thread);
    EXPECT_EQ(data, &context);

    EXPECT_EQ(context.value, 1);

    rawstd_cond_delete(context.cond);
    rawstd_mutex_delete(context.mutex);
}

TEST(CondTest, broadcast) {
    TestThreadingContext context = (TestThreadingContext){
        .mutex = rawstd_mutex_create(),
        .cond = rawstd_cond_create(),
        .wait = 0,
        .value = 0,
    };

    EXPECT_NE(context.mutex, nullptr);
    EXPECT_NE(context.cond, nullptr);

    std::vector<RawstdThread*> threads;

    for (size_t i = 0; i < 10; ++i) {
        threads.push_back(rawstd_thread_create(test_thread, &context));
    }

    while (1) {
        rawstd_mutex_lock(context.mutex);
        if (context.wait == (int)threads.size()) {
            rawstd_mutex_unlock(context.mutex);
            break;
        }
        rawstd_mutex_unlock(context.mutex);
        usleep(1000);
    }

    rawstd_mutex_lock(context.mutex);
    rawstd_cond_broadcast(context.cond);
    rawstd_mutex_unlock(context.mutex);

    for (size_t i = 0; i < threads.size(); ++i) {
        rawstd_thread_join(threads[i]);
    }

    EXPECT_EQ(context.value, (int)threads.size());

    rawstd_cond_delete(context.cond);
    rawstd_mutex_delete(context.mutex);
}

void* test_wait_thread(void* data) {
    int* timeout = static_cast<int*>(data);

    RawstdMutex* mutex = rawstd_mutex_create();
    RawstdCond* cond = rawstd_cond_create();

    assert(mutex != nullptr);
    assert(cond != nullptr);

    rawstd_mutex_lock(mutex);
    rawstd_cond_wait_timeout(cond, mutex, *timeout);
    rawstd_mutex_unlock(mutex);

    rawstd_cond_delete(cond);
    rawstd_mutex_delete(mutex);

    return nullptr;
}

TEST(CondTest, wait_timeout) {
    int timeout = 100;

    timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    RawstdThread* thread = rawstd_thread_create(test_wait_thread, &timeout);
    EXPECT_NE(thread, nullptr);
    rawstd_thread_join(thread);

    timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    long dsec = ts_end.tv_sec - ts_start.tv_sec;
    long dnsec = ts_end.tv_nsec - ts_start.tv_nsec;
    if (dnsec < 0) {
        dnsec += 1000000000;
        dsec -= 1;
    }
    long dmsec = dsec * 1000 + dnsec / 1000000;

    EXPECT_GE(dmsec, timeout);
}

} // unnamed namespace
