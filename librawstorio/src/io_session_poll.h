#ifndef RAWSTORIO_IO_SESSION_POLL_H
#define RAWSTORIO_IO_SESSION_POLL_H

#include <rawstorstd/ringbuf.h>


typedef struct RawstorIOSession {
    int fd;
    RawstorRingBuf *read_ops;
    RawstorRingBuf *write_ops;
} RawstorIOSession;


#endif // RAWSTORIO_IO_EVENT_POLL_H
