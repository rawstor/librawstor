#ifndef RAWSTORSTD_THREADING
#define RAWSTORSTD_THREADING

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstorThread RawstorThread;

typedef struct RawstorMutex RawstorMutex;

typedef struct RawstorCond RawstorCond;

typedef void*(RawstorThreadRoutine)(void* data);

RawstorThread* rawstor_thread_create(RawstorThreadRoutine* routine, void* data);

void* rawstor_thread_join(RawstorThread* thread);

void rawstor_thread_detach(RawstorThread* thread);

RawstorMutex* rawstor_mutex_create(void);

void rawstor_mutex_delete(RawstorMutex* mutex);

void rawstor_mutex_lock(RawstorMutex* mutex);

void rawstor_mutex_unlock(RawstorMutex* mutex);

RawstorCond* rawstor_cond_create(void);

void rawstor_cond_delete(RawstorCond* cond);

void rawstor_cond_wait(RawstorCond* cond, RawstorMutex* mutex);

int rawstor_cond_wait_timeout(
    RawstorCond* cond, RawstorMutex* mutex, int timeout
);

void rawstor_cond_signal(RawstorCond* cond);

void rawstor_cond_broadcast(RawstorCond* cond);

#ifdef __cplusplus
}
#endif

#endif // RAWSTORSTD_THREADING
