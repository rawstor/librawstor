#ifndef RAWSTD_THREADING
#define RAWSTD_THREADING

#ifdef __cplusplus
extern "C" {
#endif

typedef struct RawstdThread RawstdThread;

typedef struct RawstdMutex RawstdMutex;

typedef struct RawstdCond RawstdCond;

typedef void*(RawstdThreadRoutine)(void* data);

RawstdThread* rawstd_thread_create(RawstdThreadRoutine* routine, void* data);

void* rawstd_thread_join(RawstdThread* thread);

void rawstd_thread_detach(RawstdThread* thread);

RawstdMutex* rawstd_mutex_create(void);

void rawstd_mutex_delete(RawstdMutex* mutex);

void rawstd_mutex_lock(RawstdMutex* mutex);

void rawstd_mutex_unlock(RawstdMutex* mutex);

RawstdCond* rawstd_cond_create(void);

void rawstd_cond_delete(RawstdCond* cond);

void rawstd_cond_wait(RawstdCond* cond, RawstdMutex* mutex);

int rawstd_cond_wait_timeout(RawstdCond* cond, RawstdMutex* mutex, int timeout);

void rawstd_cond_signal(RawstdCond* cond);

void rawstd_cond_broadcast(RawstdCond* cond);

#ifdef __cplusplus
}
#endif

#endif // RAWSTD_THREADING
