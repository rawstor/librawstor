#ifndef RAWSTORIO_IO_SESSION_THREAD_H
#define RAWSTORIO_IO_SESSION_THREAD_H

#include "rawstorio/io.h"

#include <rawstorstd/list.h>
#include <rawstorstd/ringbuf.h>
#include <rawstorstd/threading.h>


typedef struct RawstorIOSession {
    RawstorIO *io;
    int fd;
    int write;

    RawstorRingBuf *sqes;

    int exit;
    RawstorMutex *mutex;
    RawstorCond *cond;
    RawstorList *threads;
} RawstorIOSession;


#endif // RAWSTORIO_IO_SESSION_THREAD_H
