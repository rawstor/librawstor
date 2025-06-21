#include "threading.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


struct RawstorMutex {
    pthread_mutex_t pmutex;
};


RawstorMutex* rawstor_mutex_create(void) {
    RawstorMutex *ret = malloc(sizeof(RawstorMutex));
    if (ret == NULL) {
        return NULL;
    }

    int res = pthread_mutex_init(&ret->pmutex, NULL);
    if (res != 0) {
        free(ret);
        errno = res;
        return NULL;
    }

    return ret;
}


void rawstor_mutex_delete(RawstorMutex *mutex) {
    while (1) {
        int res = pthread_mutex_destroy(&mutex->pmutex);
        if (res == EBUSY) {
            rawstor_mutex_unlock(mutex);
            continue;
        }
        break;
    }
    free(mutex);
}

void rawstor_mutex_lock(RawstorMutex *mutex) {
    int res = pthread_mutex_lock(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_lock() failed");
        exit(errno);
    }
}

void rawstor_mutex_unlock(RawstorMutex *mutex) {
    int res = pthread_mutex_unlock(&mutex->pmutex);
    if (res != 0) {
        errno = res;
        perror("pthread_mutex_unlock() failed");
        exit(errno);
    }
}
