#ifndef RAWSTORIO_QUEUE_POLL_H
#define RAWSTORIO_QUEUE_POLL_H

#include <rawstorio/event.h>
#include <rawstorio/queue.h>


#ifdef __cplusplus
extern "C" {
#endif


int rawstor_io_queue_push_cqe(RawstorIOQueue *queue, RawstorIOEvent *event);

int rawstor_io_queue_depth(RawstorIOQueue *queue);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_QUEUE_POLL_H
