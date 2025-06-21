#ifndef RAWSTOR_THREADING
#define RAWSTOR_THREADING


typedef struct RawstorMutex RawstorMutex;


RawstorMutex* rawstor_mutex_create(void);

void rawstor_mutex_delete(RawstorMutex *mutex);

void rawstor_mutex_lock(RawstorMutex *mutex);

void rawstor_mutex_unlock(RawstorMutex *mutex);


#endif // RAWSTOR_THREADING
