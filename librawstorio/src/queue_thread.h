#ifndef RAWSTORIO_QUEUE_THREAD_H
#define RAWSTORIO_QUEUE_THREAD_H

#include <rawstorio/event.h>
#include <rawstorio/queue.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_io_queue_push_cqe(RawstorIOQueue *io, RawstorIOEvent *event);

int rawstor_io_queue_push_cqes(
    RawstorIOQueue *io, RawstorIOEvent **events, size_t nevents);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_QUEUE_THREAD_H
