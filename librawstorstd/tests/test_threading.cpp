#include "rawstorstd/threading.h"

#include <gtest/gtest.h>

#include <time.h>
#include <unistd.h>

#include <vector>

#include <cassert>
#include <cstddef>
#include <cstdlib>

namespace {

struct TestThreadingContext {
    RawstorMutex* mutex;
    RawstorCond* cond;

    int wait;
    int value;
};

void* test_thread(void* data) {
    TestThreadingContext* context = static_cast<TestThreadingContext*>(data);

    rawstor_mutex_lock(context->mutex);
    ++context->wait;
    rawstor_cond_wait(context->cond, context->mutex);
    --context->wait;
    ++context->value;
    rawstor_mutex_unlock(context->mutex);

    return context;
}

TEST(CondTest, signal) {
    TestThreadingContext context = (TestThreadingContext){
        .mutex = rawstor_mutex_create(),
        .cond = rawstor_cond_create(),
        .wait = 0,
        .value = 0,
    };

    EXPECT_NE(context.mutex, nullptr);
    EXPECT_NE(context.cond, nullptr);

    RawstorThread* thread = rawstor_thread_create(test_thread, &context);

    while (1) {
        rawstor_mutex_lock(context.mutex);
        if (context.wait == 1) {
            rawstor_mutex_unlock(context.mutex);
            break;
        }
        rawstor_mutex_unlock(context.mutex);
        usleep(1000);
    }

    rawstor_mutex_lock(context.mutex);
    rawstor_cond_signal(context.cond);
    rawstor_mutex_unlock(context.mutex);

    void* data = rawstor_thread_join(thread);
    EXPECT_EQ(data, &context);

    EXPECT_EQ(context.value, 1);

    rawstor_cond_delete(context.cond);
    rawstor_mutex_delete(context.mutex);
}

TEST(CondTest, broadcast) {
    TestThreadingContext context = (TestThreadingContext){
        .mutex = rawstor_mutex_create(),
        .cond = rawstor_cond_create(),
        .wait = 0,
        .value = 0,
    };

    EXPECT_NE(context.mutex, nullptr);
    EXPECT_NE(context.cond, nullptr);

    std::vector<RawstorThread*> threads;

    for (size_t i = 0; i < 10; ++i) {
        threads.push_back(rawstor_thread_create(test_thread, &context));
    }

    while (1) {
        rawstor_mutex_lock(context.mutex);
        if (context.wait == (int)threads.size()) {
            rawstor_mutex_unlock(context.mutex);
            break;
        }
        rawstor_mutex_unlock(context.mutex);
        usleep(1000);
    }

    rawstor_mutex_lock(context.mutex);
    rawstor_cond_broadcast(context.cond);
    rawstor_mutex_unlock(context.mutex);

    for (size_t i = 0; i < threads.size(); ++i) {
        rawstor_thread_join(threads[i]);
    }

    EXPECT_EQ(context.value, (int)threads.size());

    rawstor_cond_delete(context.cond);
    rawstor_mutex_delete(context.mutex);
}

void* test_wait_thread(void* data) {
    int* timeout = static_cast<int*>(data);

    RawstorMutex* mutex = rawstor_mutex_create();
    RawstorCond* cond = rawstor_cond_create();

    assert(mutex != nullptr);
    assert(cond != nullptr);

    rawstor_mutex_lock(mutex);
    rawstor_cond_wait_timeout(cond, mutex, *timeout);
    rawstor_mutex_unlock(mutex);

    rawstor_cond_delete(cond);
    rawstor_mutex_delete(mutex);

    return nullptr;
}

TEST(CondTest, wait_timeout) {
    int timeout = 100;

    timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    RawstorThread* thread = rawstor_thread_create(test_wait_thread, &timeout);
    EXPECT_NE(thread, nullptr);
    rawstor_thread_join(thread);

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
