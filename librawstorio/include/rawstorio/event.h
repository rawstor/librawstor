#ifndef RAWSTORIO_EVENT_H
#define RAWSTORIO_EVENT_H

#include <rawstorio/queue.h>

#include <rawstor/io_event.h>

#include <stddef.h>


#ifdef __cplusplus
extern "C" {
#endif


// defined in rawstor/io_event.h
// typedef struct RawstorIOEvent RawstorIOEvent;


RawstorIOQueue* rawstor_io_event_queue(RawstorIOEvent *event);

int rawstor_io_event_fd(RawstorIOEvent *event);

size_t rawstor_io_event_size(RawstorIOEvent *event);

size_t rawstor_io_event_result(RawstorIOEvent *event);

int rawstor_io_event_error(RawstorIOEvent *event);

int rawstor_io_event_dispatch(RawstorIOEvent *event);


#ifdef __cplusplus
}
#endif


#endif // RAWSTORIO_EVENT_H
