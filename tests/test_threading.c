#include "threading.h"

#include "unittest.h"

#include <assert.h>
#include <stddef.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>


struct TestThreadingContext {
    RawstorMutex *mutex;
    RawstorCond *cond;

    int wait;
    int value;
};


static void* test_thread(void *data) {
    struct TestThreadingContext *context = data;

    rawstor_mutex_lock(context->mutex);
    ++context->wait;
    rawstor_cond_wait(context->cond, context->mutex);
    --context->wait;
    ++context->value;
    rawstor_mutex_unlock(context->mutex);

    return context;
}


static int test_cond_signal() {
    struct TestThreadingContext context = (struct TestThreadingContext) {
        .mutex = rawstor_mutex_create(),
        .cond = rawstor_cond_create(),
        .wait = 0,
        .value = 0,
    };

    assertTrue(context.mutex != NULL);
    assertTrue(context.cond != NULL);

    RawstorThread *thread = rawstor_thread_create(test_thread, &context);

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

    void *data = rawstor_thread_join(thread);
    assertTrue(data == &context);

    assertTrue(context.value == 1);

    rawstor_cond_delete(context.cond);
    rawstor_mutex_delete(context.mutex);

    return 0;
}


static int test_cond_broadcast() {
    int count = 10;

    struct TestThreadingContext context = (struct TestThreadingContext) {
        .mutex = rawstor_mutex_create(),
        .cond = rawstor_cond_create(),
        .wait = 0,
        .value = 0,
    };

    assertTrue(context.mutex != NULL);
    assertTrue(context.cond != NULL);

    RawstorThread **threads = calloc(count, sizeof(RawstorThread*));
    assertTrue(threads != NULL);

    for (int i = 0; i < count; ++i) {
        threads[i] = rawstor_thread_create(test_thread, &context);
    }

    while (1) {
        rawstor_mutex_lock(context.mutex);
        if (context.wait == count) {
            rawstor_mutex_unlock(context.mutex);
            break;
        }
        rawstor_mutex_unlock(context.mutex);
        usleep(1000);
    }

    rawstor_mutex_lock(context.mutex);
    rawstor_cond_broadcast(context.cond);
    rawstor_mutex_unlock(context.mutex);

    for (int i = 0; i < count; ++i) {
        rawstor_thread_join(threads[i]);
    }

    assertTrue(context.value == count);

    rawstor_cond_delete(context.cond);
    rawstor_mutex_delete(context.mutex);

    return 0;
}


static void* test_wait_thread(void *data) {
    int *timeout = data;

    RawstorMutex *mutex = rawstor_mutex_create();
    RawstorCond *cond = rawstor_cond_create();

    assert(mutex != NULL);
    assert(cond != NULL);

    rawstor_mutex_lock(mutex);
    rawstor_cond_wait_timeout(cond, mutex, *timeout);
    rawstor_mutex_unlock(mutex);

    rawstor_cond_delete(cond);
    rawstor_mutex_delete(mutex);

    return NULL;
}


static int test_cond_wait_timeout() {
    static int timeout = 100;

    struct timespec ts_start;
    clock_gettime(CLOCK_MONOTONIC, &ts_start);

    RawstorThread *thread = rawstor_thread_create(test_wait_thread, &timeout);
    assertTrue(thread != NULL);
    rawstor_thread_join(thread);

    struct timespec ts_end;
    clock_gettime(CLOCK_MONOTONIC, &ts_end);

    long dsec = ts_end.tv_sec - ts_start.tv_sec;
    long dnsec = ts_end.tv_nsec - ts_start.tv_nsec;
    if (dnsec < 0) {
        dnsec += 1000000000;
        dsec -= 1;
    }
    long dmsec = dsec * 1000 + dnsec / 1000000;

    assertTrue(dmsec >= timeout);

    return 0;
}


int main() {
    int rval = 0;
    rval += test_cond_signal();
    rval += test_cond_broadcast();
    rval += test_cond_wait_timeout();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
