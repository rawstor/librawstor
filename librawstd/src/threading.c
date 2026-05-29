#include "rawstd/threading.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct RawstdThread {
    pthread_t pthread;
};

struct RawstdMutex {
    pthread_mutex_t pmutex;
};

struct RawstdCond {
    pthread_cond_t pcond;
};

RawstdThread* rawstd_thread_create(RawstdThreadRoutine* routine, void* data) {
    RawstdThread* ret = malloc(sizeof(RawstdThread));
    if (ret == NULL) {
        return NULL;
    }

    int res = pthread_create(&ret->pthread, NULL, routine, data);
    if (res != 0) {
        errno = res;
        free(ret);
        return NULL;
    }

    return ret;
}

void* rawstd_thread_join(RawstdThread* thread) {
    void* data;

    int res = pthread_join(thread->pthread, &data);
    if (res != 0) {
        errno = res;
        perror("pthread_join() failed");
        exit(errno);
    }

    free(thread);

    return data;
}

void rawstd_thread_detach(RawstdThread* thread) {
    int res = pthread_detach(thread->pthread);
    if (res != 0) {
        errno = res;
        perror("pthread_detach() failed");
        exit(errno);
    }

    free(thread);
}

RawstdMutex* rawstd_mutex_create(void) {
    RawstdMutex* ret = malloc(sizeof(RawstdMutex));
    if (ret == NULL) {
        return NULL;
    }

    int res = pthread_mutex_init(&ret->pmutex, NULL);
    if (res != 0) {
        errno = res;
        free(ret);
        return NULL;
    }

    return ret;
}

void rawstd_mutex_delete(RawstdMutex* mutex) {
    int res = pthread_mutex_destroy(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_destroy() failed");
        exit(errno);
    }
    free(mutex);
}

void rawstd_mutex_lock(RawstdMutex* mutex) {
    int res = pthread_mutex_lock(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_lock() failed");
        exit(errno);
    }
}

void rawstd_mutex_unlock(RawstdMutex* mutex) {
    int res = pthread_mutex_unlock(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_unlock() failed");
        exit(errno);
    }
}

RawstdCond* rawstd_cond_create(void) {
    RawstdCond* ret = malloc(sizeof(RawstdCond));
    if (ret == NULL) {
        return NULL;
    }

    int res = pthread_cond_init(&ret->pcond, NULL);
    if (res != 0) {
        errno = res;
        free(ret);
        return NULL;
    }

    return ret;
}

void rawstd_cond_delete(RawstdCond* cond) {
    int res = pthread_cond_destroy(&cond->pcond);
    if (res != 0) {
        errno = res;
        perror("pthread_cond_destroy() failed");
        exit(errno);
    }
    free(cond);
}

void rawstd_cond_wait(RawstdCond* cond, RawstdMutex* mutex) {
    int res = pthread_cond_wait(&cond->pcond, &mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("rawstd_cond_wait() failed");
        exit(errno);
    }
}

int rawstd_cond_wait_timeout(
    RawstdCond* cond, RawstdMutex* mutex, int timeout
) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    ts.tv_sec += timeout / 1000;
    ts.tv_nsec += 1000000l * (timeout % 1000);
    ts.tv_sec += ts.tv_nsec / 1000000000;
    ts.tv_nsec %= 1000000000;

    int res = pthread_cond_timedwait(&cond->pcond, &mutex->pmutex, &ts);
    if (res != 0) {
        if (res != ETIMEDOUT) {
            errno = res;
            perror("pthread_cond_timedwait() failed");
            exit(errno);
        }
        return 0;
    }

    return 1;
}

void rawstd_cond_signal(RawstdCond* cond) {
    int res = pthread_cond_signal(&cond->pcond);
    if (res != 0) {
        errno = res;
        perror("pthread_cond_signal() failed");
        exit(errno);
    }
}

void rawstd_cond_broadcast(RawstdCond* cond) {
    int res = pthread_cond_broadcast(&cond->pcond);
    if (res != 0) {
        errno = res;
        perror("pthread_cond_broadcast() failed");
        exit(errno);
    }
}
