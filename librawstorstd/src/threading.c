#include "rawstorstd/threading.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

struct RawstorThread {
    pthread_t pthread;
};

struct RawstorMutex {
    pthread_mutex_t pmutex;
};

struct RawstorCond {
    pthread_cond_t pcond;
};

RawstorThread*
rawstor_thread_create(RawstorThreadRoutine* routine, void* data) {
    RawstorThread* ret = malloc(sizeof(RawstorThread));
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

void* rawstor_thread_join(RawstorThread* thread) {
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

void rawstor_thread_detach(RawstorThread* thread) {
    int res = pthread_detach(thread->pthread);
    if (res != 0) {
        errno = res;
        perror("pthread_detach() failed");
        exit(errno);
    }

    free(thread);
}

RawstorMutex* rawstor_mutex_create(void) {
    RawstorMutex* ret = malloc(sizeof(RawstorMutex));
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

void rawstor_mutex_delete(RawstorMutex* mutex) {
    int res = pthread_mutex_destroy(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_destroy() failed");
        exit(errno);
    }
    free(mutex);
}

void rawstor_mutex_lock(RawstorMutex* mutex) {
    int res = pthread_mutex_lock(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_lock() failed");
        exit(errno);
    }
}

void rawstor_mutex_unlock(RawstorMutex* mutex) {
    int res = pthread_mutex_unlock(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_unlock() failed");
        exit(errno);
    }
}

RawstorCond* rawstor_cond_create(void) {
    RawstorCond* ret = malloc(sizeof(RawstorCond));
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

void rawstor_cond_delete(RawstorCond* cond) {
    int res = pthread_cond_destroy(&cond->pcond);
    if (res != 0) {
        errno = res;
        perror("pthread_cond_destroy() failed");
        exit(errno);
    }
    free(cond);
}

void rawstor_cond_wait(RawstorCond* cond, RawstorMutex* mutex) {
    int res = pthread_cond_wait(&cond->pcond, &mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("rawstor_cond_wait() failed");
        exit(errno);
    }
}

int rawstor_cond_wait_timeout(
    RawstorCond* cond, RawstorMutex* mutex, int timeout
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

void rawstor_cond_signal(RawstorCond* cond) {
    int res = pthread_cond_signal(&cond->pcond);
    if (res != 0) {
        errno = res;
        perror("pthread_cond_signal() failed");
        exit(errno);
    }
}

void rawstor_cond_broadcast(RawstorCond* cond) {
    int res = pthread_cond_broadcast(&cond->pcond);
    if (res != 0) {
        errno = res;
        perror("pthread_cond_broadcast() failed");
        exit(errno);
    }
}
