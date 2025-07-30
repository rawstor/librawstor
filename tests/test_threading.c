#include "threading.h"

#include "utils.h"

#include <stddef.h>
#include <stdlib.h>
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

    void *data;
    int res = rawstor_thread_join(thread, &data);
    assertTrue(res == 0);
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
        int res = rawstor_thread_join(threads[i], NULL);
        assertTrue(res == 0);
    }

    assertTrue(context.value == count);

    rawstor_cond_delete(context.cond);
    rawstor_mutex_delete(context.mutex);

    return 0;
}


int main() {
    int rval = 0;
    rval += test_cond_signal();
    rval += test_cond_broadcast();
    return rval ? EXIT_FAILURE : EXIT_SUCCESS;
}
